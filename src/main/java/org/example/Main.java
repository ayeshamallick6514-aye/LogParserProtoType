package org.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LogAnchor-X Backend
 *
 * Pure JDK 17, zero external dependencies, zero external network calls.
 * Single process, single file, designed to run air-gapped.
 *
 * Pipeline: format-detect -> mask volatile fields -> Drain template mining
 *           -> MITRE heuristic tagging -> triple-key correlation
 *           -> SHA-256 leaf hash (over ORIGINAL raw bytes, always)
 *           -> Merkle batch anchoring -> cross-batch hash chain -> ledger file.
 */
public class Main {

    static final int PORT = 8080;
    static final int BATCH_SIZE = 64;
    static final long CORRELATION_WINDOW_SECONDS = 600;
    static final Path LEDGER_FILE = Paths.get("cyberguard_ledger.dat");

    public static void main(String[] args) throws IOException {
        Engine engine = new Engine();
        engine.loadLedger();

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        server.createContext("/", new StaticHandler());
        server.createContext("/api/parse", new ParseHandler(engine));
        server.createContext("/api/verify", new VerifyHandler(engine));
        server.createContext("/api/tamper-simulate", new TamperHandler(engine));
        server.createContext("/api/mitre-matrix", new MitreMatrixHandler(engine));
        server.createContext("/api/logs-by-technique", new LogsByTechniqueHandler(engine));
        server.createContext("/api/provenance-graph", new ProvenanceGraphHandler(engine));
        server.createContext("/api/evidence-bundle", new EvidenceBundleHandler(engine));
        server.createContext("/api/simulate-attack", new SimulateAttackHandler(engine));
        server.createContext("/api/status", new StatusHandler(engine));
        server.createContext("/api/anchor", new AnchorHandler(engine));
        server.createContext("/api/reset", new ResetHandler(engine));

        int poolSize = Math.max(4, Runtime.getRuntime().availableProcessors() * 2);
        server.setExecutor(Executors.newFixedThreadPool(poolSize));
        server.start();

        System.out.println("==========================================================");
        System.out.println("[OK] LogAnchor-X Unified Backend Live on http://localhost:" + PORT);
        System.out.println("[OK] Bounded Pool: " + poolSize + " workers | Air-Gap Ready");
        System.out.println("==========================================================");
    }

    // ============================================================
    // Core data model
    // ============================================================
    static class LogEvent {
        String id;
        String rawText;
        String maskedText;
        String templateId;
        String templateText;
        boolean templateIsNovel;
        String format;
        long timestampMillis;

        String sourceIp;
        String destPort;
        String serviceType;

        String mitreTactic;
        String mitreTacticId;
        String mitreTechnique;
        String mitreTechniqueId;
        int killChainOrder;

        String leafHash;
        String batchId;
        int leafIndexInBatch = -1;
        List<String> merkleSiblingPath = new ArrayList<>();

        Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("raw", rawText);
            m.put("masked", maskedText);
            m.put("template", templateText);
            m.put("templateId", templateId);
            m.put("templateIsNovel", templateIsNovel);
            m.put("format", format);
            m.put("timestamp", timestampMillis);
            m.put("sourceIp", sourceIp != null ? sourceIp : "UNKNOWN_SRC");
            m.put("destPort", destPort != null ? destPort : "0");
            m.put("service", serviceType != null ? serviceType : "SYSTEM");
            m.put("mitreTacticName", mitreTactic);
            m.put("mitreTacticId", mitreTacticId);
            m.put("mitreTechnique", mitreTechnique);
            m.put("mitreId", mitreTechniqueId);
            m.put("stage", killChainOrder);
            m.put("leafHash", leafHash);
            m.put("batchId", batchId);
            m.put("sealed", batchId != null);
            return m;
        }
    }

    // ============================================================
    // Format detection
    // ============================================================
    static class FormatAdapter {
        static final Pattern CSV_LIKE = Pattern.compile("^[^,]+,[^,]+,[^,]+");

        static String detect(String raw) {
            String trimmed = raw.trim();
            if (trimmed.startsWith("CEF:")) return "CEF";
            if (trimmed.startsWith("LEEF:")) return "LEEF";
            if ((trimmed.startsWith("{") && trimmed.endsWith("}")) ||
                    (trimmed.startsWith("[") && trimmed.endsWith("]"))) return "JSON";
            if (trimmed.startsWith("<") && trimmed.endsWith(">")) return "XML";
            if (CSV_LIKE.matcher(trimmed).find() && trimmed.split(",").length >= 3) return "CSV";
            return "SYSLOG";
        }
    }

    // ============================================================
    // Volatile-field masking
    // ============================================================
    static class Masker {
        static final Pattern IP = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        static final Pattern PORT = Pattern.compile("(?:dpt=|port\\s+|spt=|:)(\\d{2,5})\\b", Pattern.CASE_INSENSITIVE);
        static final Pattern UUID = Pattern.compile(
                "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b");
        static final Pattern HEX = Pattern.compile("\\b0x[0-9a-fA-F]+\\b");
        static final Pattern TIMESTAMP1 = Pattern.compile(
                "\\b\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z)?\\b");
        static final Pattern TIMESTAMP2 = Pattern.compile(
                "\\b[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\b");
        static final Pattern NUMBER = Pattern.compile("\\b\\d+\\b");

        static String mask(String raw) {
            String s = raw;
            s = TIMESTAMP1.matcher(s).replaceAll("<TS>");
            s = TIMESTAMP2.matcher(s).replaceAll("<TS>");
            s = IP.matcher(s).replaceAll("<IP>");
            s = UUID.matcher(s).replaceAll("<UUID>");
            s = HEX.matcher(s).replaceAll("<HEX>");
            s = NUMBER.matcher(s).replaceAll("<N>");
            return s;
        }

        static String extractIp(String raw) {
            Matcher m = IP.matcher(raw);
            return m.find() ? m.group() : "UNKNOWN_SRC";
        }

        static String extractPort(String raw) {
            Matcher m = PORT.matcher(raw);
            return m.find() ? m.group(1) : "0";
        }

        static String extractService(String raw) {
            String l = raw.toLowerCase();
            if (l.contains("sshd") || l.contains("ssh")) return "SSH";
            if (l.contains("sudo")) return "SUDO";
            if (l.contains("firewall") || l.contains("fw") || l.contains("proto=tcp")) return "FIREWALL";
            if (l.contains("proxy") || l.contains("http") || l.contains("nginx")) return "PROXY";
            if (l.contains("select") || l.contains("db") || l.contains("mysqld") || l.contains("postgres")) return "DATABASE";
            return "SYSTEM";
        }
    }

    // ============================================================
    // Drain Template Miner
    // ============================================================
    static class TemplateCluster {
        String id;
        List<String> tokens;
        int matchCount = 1;
    }

    static class DrainTree {
        final Map<Integer, Map<String, List<TemplateCluster>>> tree = new ConcurrentHashMap<>();
        final AtomicInteger clusterCounter = new AtomicInteger(0);
        static final double SIM_THRESHOLD = 0.5;

        static List<String> tokenize(String masked) {
            return Arrays.asList(masked.trim().split("\\s+"));
        }

        synchronized Object[] match(String masked) {
            List<String> tokens = tokenize(masked);
            int len = tokens.size();
            String firstTok = tokens.isEmpty() ? "" : tokens.get(0);

            Map<String, List<TemplateCluster>> byFirstTok =
                    tree.computeIfAbsent(len, k -> new ConcurrentHashMap<>());
            List<TemplateCluster> candidates =
                    byFirstTok.computeIfAbsent(firstTok, k -> new ArrayList<>());

            TemplateCluster best = null;
            double bestSim = -1;
            for (TemplateCluster c : candidates) {
                double sim = similarity(c.tokens, tokens);
                if (sim > bestSim) { bestSim = sim; best = c; }
            }

            if (best != null && bestSim >= SIM_THRESHOLD) {
                for (int i = 0; i < len; i++) {
                    if (!best.tokens.get(i).equals("<*>") && !best.tokens.get(i).equals(tokens.get(i))) {
                        best.tokens.set(i, "<*>");
                    }
                }
                best.matchCount++;
                return new Object[]{best.id, String.join(" ", best.tokens), false};
            } else {
                TemplateCluster nc = new TemplateCluster();
                nc.id = "T" + clusterCounter.incrementAndGet();
                nc.tokens = new ArrayList<>(tokens);
                candidates.add(nc);
                return new Object[]{nc.id, String.join(" ", nc.tokens), true};
            }
        }

        static double similarity(List<String> a, List<String> b) {
            if (a.size() != b.size() || a.isEmpty()) return 0;
            int match = 0;
            for (int i = 0; i < a.size(); i++) {
                if (a.get(i).equals("<*>") || a.get(i).equals(b.get(i))) match++;
            }
            return (double) match / a.size();
        }
    }

    // ============================================================
    // MITRE Classifier (14 Enterprise Tactics)
    // ============================================================
    static class MitreClassifier {
        static final List<String[]> MITRE_14_TACTICS = List.of(
                new String[]{"TA0043", "Reconnaissance"},
                new String[]{"TA0042", "Resource Development"},
                new String[]{"TA0001", "Initial Access"},
                new String[]{"TA0002", "Execution"},
                new String[]{"TA0003", "Persistence"},
                new String[]{"TA0004", "Privilege Escalation"},
                new String[]{"TA0005", "Defense Evasion"},
                new String[]{"TA0006", "Credential Access"},
                new String[]{"TA0007", "Discovery"},
                new String[]{"TA0008", "Lateral Movement"},
                new String[]{"TA0009", "Collection"},
                new String[]{"TA0011", "Command and Control"},
                new String[]{"TA0010", "Exfiltration"},
                new String[]{"TA0040", "Impact"}
        );

        static Object[] classify(String rawLower) {
            if (rawLower.contains("failed password") || rawLower.contains("authentication failure")
                    || rawLower.contains("login denied") || rawLower.contains("auth error")) {
                return new Object[]{"Credential Access", "TA0006", "Brute Force", "T1110", 3};
            }
            if (rawLower.contains("sudo") || rawLower.contains("privilege escalation") || rawLower.contains("root access")) {
                return new Object[]{"Privilege Escalation", "TA0004", "Valid Accounts", "T1078", 4};
            }
            if (rawLower.contains("large_transfer") || rawLower.contains("export")
                    || rawLower.contains("data_exfil") || rawLower.contains("download") || rawLower.contains("52428800")) {
                return new Object[]{"Exfiltration", "TA0010", "Exfiltration Over C2 Channel", "T1041", 6};
            }
            if (rawLower.contains("port_scan") || rawLower.contains("scan") || rawLower.contains("connection attempt")) {
                return new Object[]{"Reconnaissance", "TA0043", "Network Service Discovery", "T1046", 1};
            }
            if (rawLower.contains("ssh2") || rawLower.contains("accepted password") || rawLower.contains("remote")) {
                return new Object[]{"Lateral Movement", "TA0008", "Remote Services", "T1021", 5};
            }
            return new Object[]{"Unclassified", "UNCLASSIFIED", "Unknown/Novel Pattern", "UNCLASSIFIED", 0};
        }
    }

    // ============================================================
    // Merkle Tree & Proof Recomputation
    // ============================================================
    static class Batch {
        String batchId;
        List<LogEvent> events = new ArrayList<>();
        String merkleRoot;
        String chainedRoot;
        long sealedAtMillis;
    }

    static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static class MerkleBuilder {
        static String build(List<LogEvent> events) {
            if (events.isEmpty()) return sha256Hex("");
            recomputeSiblingPaths(events);

            List<String> level = new ArrayList<>();
            for (LogEvent e : events) level.add(e.leafHash);

            while (level.size() > 1) {
                List<String> next = new ArrayList<>();
                for (int i = 0; i < level.size(); i += 2) {
                    String left = level.get(i);
                    String right = (i + 1 < level.size()) ? level.get(i + 1) : level.get(i);
                    next.add(sha256Hex(left + right));
                }
                level = next;
            }
            return level.get(0);
        }

        static void recomputeSiblingPaths(List<LogEvent> events) {
            List<String> level = new ArrayList<>();
            for (LogEvent e : events) {
                level.add(e.leafHash);
                e.merkleSiblingPath = new ArrayList<>();
            }
            List<List<Integer>> owners = new ArrayList<>();
            for (int i = 0; i < level.size(); i++) {
                List<Integer> o = new ArrayList<>(); o.add(i); owners.add(o);
            }

            while (level.size() > 1) {
                List<String> next = new ArrayList<>();
                List<List<Integer>> nextOwners = new ArrayList<>();
                for (int i = 0; i < level.size(); i += 2) {
                    String left = level.get(i);
                    boolean hasRight = i + 1 < level.size();
                    String right = hasRight ? level.get(i + 1) : level.get(i);

                    for (int ownerIdx : owners.get(i)) {
                        events.get(ownerIdx).merkleSiblingPath.add(right);
                    }
                    if (hasRight) {
                        for (int ownerIdx : owners.get(i + 1)) {
                            events.get(ownerIdx).merkleSiblingPath.add(left);
                        }
                    }
                    next.add(sha256Hex(left + right));
                    List<Integer> merged = new ArrayList<>(owners.get(i));
                    if (hasRight) merged.addAll(owners.get(i + 1));
                    nextOwners.add(merged);
                }
                level = next;
                owners = nextOwners;
            }
        }

        static String recomputeRoot(String leafHash, List<String> siblingPath) {
            String current = leafHash;
            for (String sibling : siblingPath) {
                current = sha256Hex(current + sibling);
            }
            return current;
        }
    }

    // ============================================================
    // Engine: Runtime Orchestrator
    // ============================================================
    static class Engine {
        final DrainTree drainTree = new DrainTree();
        final Map<String, LogEvent> eventsById = new ConcurrentHashMap<>();
        final Map<String, LogEvent> eventsByHash = new ConcurrentHashMap<>();
        final List<LogEvent> pendingBuffer = Collections.synchronizedList(new ArrayList<>());
        final List<Batch> sealedBatches = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger eventCounter = new AtomicInteger(0);
        final AtomicInteger batchCounter = new AtomicInteger(0);
        final AtomicInteger integrityChecksPassed = new AtomicInteger(0);
        final Set<String> detectedFormats = ConcurrentHashMap.newKeySet();
        final Map<String, Integer> mitreTechniqueCounts = new ConcurrentHashMap<>();

        volatile String lastChainedRoot = "GENESIS";
        volatile boolean simRunning = false;
        volatile String simCurrentStage = "IDLE";

        final Object ledgerLock = new Object();

        LogEvent ingest(String raw) {
            LogEvent e = new LogEvent();
            e.id = "EVT_" + eventCounter.incrementAndGet();
            e.rawText = raw.trim();
            e.timestampMillis = System.currentTimeMillis();
            e.format = FormatAdapter.detect(raw);
            detectedFormats.add(e.format);

            e.maskedText = Masker.mask(e.rawText);

            Object[] tmpl = drainTree.match(e.maskedText);
            e.templateId = (String) tmpl[0];
            e.templateText = (String) tmpl[1];
            e.templateIsNovel = (Boolean) tmpl[2];

            e.sourceIp = Masker.extractIp(e.rawText);
            e.destPort = Masker.extractPort(e.rawText);
            e.serviceType = Masker.extractService(e.rawText);

            Object[] mitre = MitreClassifier.classify(e.rawText.toLowerCase());
            e.mitreTactic = (String) mitre[0];
            e.mitreTacticId = (String) mitre[1];
            e.mitreTechnique = (String) mitre[2];
            e.mitreTechniqueId = (String) mitre[3];
            e.killChainOrder = (Integer) mitre[4];

            if (!e.mitreTechniqueId.isEmpty() && !"UNCLASSIFIED".equals(e.mitreTechniqueId)) {
                mitreTechniqueCounts.merge(e.mitreTechniqueId, 1, Integer::sum);
            }

            // Invariant: SHA-256 is strictly computed over original raw input bytes
            e.leafHash = sha256Hex(e.rawText);

            eventsById.put(e.id, e);
            eventsByHash.put(e.leafHash, e);
            pendingBuffer.add(e);

            if (pendingBuffer.size() >= BATCH_SIZE) sealBatch();
            return e;
        }

        synchronized Batch sealBatch() {
            if (pendingBuffer.isEmpty()) return null;
            Batch b = new Batch();
            b.batchId = "BATCH_" + batchCounter.incrementAndGet();
            synchronized (pendingBuffer) {
                b.events.addAll(pendingBuffer);
                pendingBuffer.clear();
            }
            b.merkleRoot = MerkleBuilder.build(b.events);
            b.chainedRoot = sha256Hex(b.merkleRoot + lastChainedRoot);
            b.sealedAtMillis = System.currentTimeMillis();
            lastChainedRoot = b.chainedRoot;

            for (int i = 0; i < b.events.size(); i++) {
                LogEvent e = b.events.get(i);
                e.batchId = b.batchId;
                e.leafIndexInBatch = i;
            }
            sealedBatches.add(b);
            appendLedger(b);
            return b;
        }

        void appendLedger(Batch b) {
            synchronized (ledgerLock) {
                try (BufferedWriter w = Files.newBufferedWriter(
                        LEDGER_FILE, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                    w.write(b.batchId + "\t" + b.merkleRoot + "\t" + b.chainedRoot
                            + "\t" + b.sealedAtMillis + "\t" + b.events.size());
                    w.newLine();
                } catch (IOException ex) {
                    System.err.println("[!] Ledger write failed: " + ex.getMessage());
                }
            }
        }

        void loadLedger() {
            if (!Files.exists(LEDGER_FILE)) return;
            try {
                List<String> lines = Files.readAllLines(LEDGER_FILE, StandardCharsets.UTF_8);
                for (String line : lines) {
                    String[] parts = line.split("\t");
                    if (parts.length >= 3) {
                        lastChainedRoot = parts[2];
                    }
                }
                System.out.println("[+] Loaded " + lines.size() + " ledger rows. Tip: " + lastChainedRoot.substring(0, Math.min(16, lastChainedRoot.length())) + "...");
            } catch (Exception e) {
                System.err.println("[!] Ledger recovery error: " + e.getMessage());
            }
        }

        int calculateThreatScore() {
            Set<Integer> activeStages = new HashSet<>();
            for (LogEvent e : eventsById.values()) {
                if (e.killChainOrder > 0) activeStages.add(e.killChainOrder);
            }
            int count = activeStages.size();
            if (count == 1) return 25;
            if (count == 2) return 55;
            if (count == 3) return 78;
            if (count >= 4) return 96;
            return 0;
        }

        List<Map<String, Object>> buildGraphEdges(List<LogEvent> events) {
            List<Map<String, Object>> edges = new ArrayList<>();
            for (int i = 0; i < events.size(); i++) {
                LogEvent b = events.get(i);
                if (b.killChainOrder <= 1) continue;

                LogEvent bestParent = null;
                double maxScore = -1.0;
                String bestConfidence = "LOW";
                long bestDelta = 0;

                for (int j = i - 1; j >= 0; j--) {
                    LogEvent a = events.get(j);
                    if (a.killChainOrder == 0 || a.killChainOrder > b.killChainOrder) continue;

                    long deltaMs = b.timestampMillis - a.timestampMillis;
                    if (deltaMs < 0 || deltaMs > CORRELATION_WINDOW_SECONDS * 1000) continue;

                    int stageDiff = b.killChainOrder - a.killChainOrder;
                    double stageScore = (stageDiff == 1) ? 50.0 : (stageDiff == 0 ? 20.0 : 10.0);

                    double keyScore = 0.0;
                    boolean sameIp = !a.sourceIp.equals("UNKNOWN_SRC") && a.sourceIp.equals(b.sourceIp);
                    boolean samePort = !a.destPort.equals("0") && a.destPort.equals(b.destPort);
                    boolean sameService = !a.serviceType.equals("SYSTEM") && a.serviceType.equals(b.serviceType);

                    if (sameIp) keyScore += 40.0;
                    if (samePort) keyScore += 20.0;
                    if (sameService) keyScore += 15.0;

                    double totalScore = stageScore + keyScore - (deltaMs / 1000.0) * 0.05;

                    if (totalScore > maxScore) {
                        maxScore = totalScore;
                        bestParent = a;
                        bestDelta = deltaMs / 1000;
                        bestConfidence = (sameIp && stageDiff <= 1) ? "HIGH (Kill-Chain Verified)" : "MODERATE (IP-Coincident)";
                    }
                }

                if (bestParent != null && maxScore > 20.0) {
                    Map<String, Object> edge = new LinkedHashMap<>();
                    edge.put("source", bestParent.id);
                    edge.put("target", b.id);
                    edge.put("confidence", bestConfidence);
                    edge.put("timeGapSec", bestDelta);
                    edges.add(edge);
                }
            }
            return edges;
        }
    }

    // ============================================================
    // JSON & HTTP Helpers
    // ============================================================
    static void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    static String readBody(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    static Map<String, String> queryParams(HttpExchange ex) {
        Map<String, String> params = new HashMap<>();
        String query = ex.getRequestURI().getQuery();
        if (query == null) return params;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                params.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return params;
    }

    static String extractJsonField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    static class Json {
        static String write(Object o) {
            StringBuilder sb = new StringBuilder();
            writeVal(o, sb);
            return sb.toString();
        }
        @SuppressWarnings("unchecked")
        static void writeVal(Object o, StringBuilder sb) {
            if (o == null) { sb.append("null"); return; }
            if (o instanceof String) { sb.append('"').append(escape((String) o)).append('"'); return; }
            if (o instanceof Number || o instanceof Boolean) { sb.append(o.toString()); return; }
            if (o instanceof Map) {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<String, Object> en : ((Map<String, Object>) o).entrySet()) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append('"').append(escape(en.getKey())).append("\":");
                    writeVal(en.getValue(), sb);
                }
                sb.append('}');
                return;
            }
            if (o instanceof Collection) {
                sb.append('[');
                boolean first = true;
                for (Object item : (Collection<?>) o) {
                    if (!first) sb.append(',');
                    first = false;
                    writeVal(item, sb);
                }
                sb.append(']');
                return;
            }
            sb.append('"').append(escape(o.toString())).append('"');
        }
        static String escape(String s) {
            StringBuilder sb = new StringBuilder();
            for (char c : s.toCharArray()) {
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                        else sb.append(c);
                }
            }
            return sb.toString();
        }
    }

    // ============================================================
    // HTTP Handlers (Integrated With Front-End Contracts)
    // ============================================================
    static class StaticHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            InputStream is = Main.class.getClassLoader().getResourceAsStream("index.html");
            if (is == null) {
                byte[] msg = "404 index.html not found in classpath".getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(404, msg.length);
                try (OutputStream os = ex.getResponseBody()) { os.write(msg); }
                return;
            }
            byte[] bytes = is.readAllBytes();
            ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            ex.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
        }
    }

    static class ParseHandler implements HttpHandler {
        final Engine engine;
        ParseHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { ex.sendResponseHeaders(405, -1); return; }
            String body = readBody(ex);
            String raw = extractJsonField(body, "log");
            if (raw == null || raw.isEmpty()) raw = body.trim();
            if (raw.isEmpty()) { sendJson(ex, 400, Map.of("error", "missing log payload")); return; }
            LogEvent e = engine.ingest(raw);
            sendJson(ex, 200, e.toJson());
        }
    }

    static class VerifyHandler implements HttpHandler {
        final Engine engine;
        VerifyHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            Map<String, String> q = queryParams(ex);
            String leaf = q.get("leafHash");
            LogEvent e = leaf == null ? null : engine.eventsByHash.get(leaf);

            if (e == null) { sendJson(ex, 404, Map.of("valid", false, "message", "Leaf hash not found in session.")); return; }
            if (e.batchId == null) { sendJson(ex, 409, Map.of("valid", false, "message", "Event not yet anchored in a batch. Click 'Seal Batch'.")); return; }

            Batch b = engine.sealedBatches.stream().filter(batch -> batch.batchId.equals(e.batchId)).findFirst().orElse(null);
            if (b == null) { sendJson(ex, 404, Map.of("valid", false, "message", "Batch not found in memory.")); return; }

            String recomputed = MerkleBuilder.recomputeRoot(e.leafHash, e.merkleSiblingPath);
            boolean valid = recomputed.equals(b.merkleRoot);
            if (valid) engine.integrityChecksPassed.incrementAndGet();

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("valid", valid);
            resp.put("leafHash", e.leafHash);
            resp.put("batchId", b.batchId);
            resp.put("recomputedRoot", recomputed);
            resp.put("anchoredRoot", b.merkleRoot);
            resp.put("chainedRoot", b.chainedRoot);
            resp.put("proofPath", e.merkleSiblingPath);
            resp.put("message", valid ? "Cryptographic proof validated against anchored Merkle root." : "Tamper detected!");
            sendJson(ex, 200, resp);
        }
    }

    static class TamperHandler implements HttpHandler {
        final Engine engine;
        TamperHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { ex.sendResponseHeaders(405, -1); return; }
            String body = readBody(ex);
            String leaf = extractJsonField(body, "leafHash");
            LogEvent e = leaf == null ? null : engine.eventsByHash.get(leaf);

            if (e == null || e.batchId == null) {
                sendJson(ex, 404, Map.of("valid", false, "message", "Event not found or not yet anchored in a sealed batch."));
                return;
            }

            Batch b = engine.sealedBatches.stream().filter(batch -> batch.batchId.equals(e.batchId)).findFirst().orElse(null);

            // Sandboxed: Flip 1 char in memory only, real ledger pristine
            char[] chars = e.rawText.toCharArray();
            int mid = chars.length / 2;
            chars[mid] = (char) (chars[mid] == 'X' ? 'Y' : 'X');
            String tamperedRaw = new String(chars);
            String tamperedLeaf = sha256Hex(tamperedRaw);

            String recomputed = MerkleBuilder.recomputeRoot(tamperedLeaf, e.merkleSiblingPath);

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("valid", false);
            resp.put("originalLeafHash", e.leafHash);
            resp.put("tamperedLeafHash", tamperedLeaf);
            resp.put("batchId", b.batchId);
            resp.put("recomputedRoot", recomputed);
            resp.put("anchoredRoot", b.merkleRoot);
            resp.put("proofPath", e.merkleSiblingPath);
            resp.put("message", "INTEGRITY VIOLATION DETECTED: 1-bit scratch mutation broke Merkle root recomputation.");
            sendJson(ex, 200, resp);
        }
    }

    static class MitreMatrixHandler implements HttpHandler {
        final Engine engine;
        MitreMatrixHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            List<Map<String, Object>> tacticsList = new ArrayList<>();
            for (String[] t : MitreClassifier.MITRE_14_TACTICS) {
                Map<String, Object> tacObj = new LinkedHashMap<>();
                tacObj.put("id", t[0]);
                tacObj.put("name", t[1]);

                List<Map<String, Object>> techList = new ArrayList<>();
                switch (t[0]) {
                    case "TA0043": techList.add(techItem("T1046", "Network Service Discovery")); break;
                    case "TA0001": techList.add(techItem("T1190", "Exploit Public-Facing App")); break;
                    case "TA0002": techList.add(techItem("T1059", "Command & Scripting")); break;
                    case "TA0003": techList.add(techItem("T1053", "Scheduled Task/Job")); break;
                    case "TA0004": techList.add(techItem("T1078", "Valid Accounts")); break;
                    case "TA0006": techList.add(techItem("T1110", "Brute Force")); break;
                    case "TA0008": techList.add(techItem("T1021", "Remote Services")); break;
                    case "TA0010": techList.add(techItem("T1041", "Exfiltration Over C2")); break;
                }
                tacObj.put("techniques", techList);
                tacticsList.add(tacObj);
            }

            Map<String, Object> unclass = new LinkedHashMap<>();
            unclass.put("id", "UNCLASSIFIED");
            unclass.put("name", "Novel / Unclassified");
            unclass.put("techniques", List.of(techItem("UNCLASSIFIED", "Unknown Pattern")));
            tacticsList.add(unclass);

            sendJson(ex, 200, Map.of("tactics", tacticsList, "totalTechniquesDetected", engine.mitreTechniqueCounts.size()));
        }

        private Map<String, Object> techItem(String id, String name) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("name", name);
            m.put("count", engine.mitreTechniqueCounts.getOrDefault(id, 0));
            return m;
        }
    }

    static class LogsByTechniqueHandler implements HttpHandler {
        final Engine engine;
        LogsByTechniqueHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            Map<String, String> q = queryParams(ex);
            String techId = q.get("techniqueId");

            List<Map<String, Object>> matched = new ArrayList<>();
            for (LogEvent e : engine.eventsById.values()) {
                if (techId == null || techId.isEmpty() || e.mitreTechniqueId.equalsIgnoreCase(techId)) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("ts", e.timestampMillis);
                    m.put("raw", e.rawText);
                    m.put("leafHash", e.leafHash);
                    m.put("mitreId", e.mitreTechniqueId);
                    m.put("mitreTechnique", e.mitreTechnique);
                    m.put("tactic", e.mitreTactic);
                    matched.add(m);
                    if (matched.size() >= 30) break;
                }
            }
            sendJson(ex, 200, Map.of("techniqueId", techId != null ? techId : "ALL", "matchedCount", matched.size(), "events", matched));
        }
    }

    static class ProvenanceGraphHandler implements HttpHandler {
        final Engine engine;
        ProvenanceGraphHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            List<LogEvent> events = new ArrayList<>(engine.eventsById.values());
            int start = Math.max(0, events.size() - 40);
            List<LogEvent> workingSet = events.subList(start, events.size());

            List<Map<String, Object>> nodes = new ArrayList<>();
            for (LogEvent e : workingSet) {
                if ("UNCLASSIFIED".equalsIgnoreCase(e.mitreTechniqueId)) continue;
                nodes.add(e.toJson());
            }

            List<Map<String, Object>> edges = engine.buildGraphEdges(workingSet);
            sendJson(ex, 200, Map.of("nodes", nodes, "edges", edges, "totalNodes", nodes.size(), "totalEdges", edges.size()));
        }
    }

    static class EvidenceBundleHandler implements HttpHandler {
        final Engine engine;
        EvidenceBundleHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            List<Map<String, Object>> verifiedNodes = new ArrayList<>();
            for (LogEvent e : engine.eventsById.values()) {
                Map<String, Object> m = e.toJson();
                m.put("siblingPath", e.merkleSiblingPath);
                verifiedNodes.add(m);
            }

            Map<String, Object> bundle = new LinkedHashMap<>();
            bundle.put("manifestType", "LogAnchor-X Forensic Evidence Bundle");
            bundle.put("timestamp", System.currentTimeMillis());
            bundle.put("chainTip", engine.lastChainedRoot);
            bundle.put("totalBatchesAnchored", engine.sealedBatches.size());
            bundle.put("nodesWithCryptographicProofs", verifiedNodes);

            byte[] jsonBytes = Json.write(bundle).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"loganchor_evidence_bundle.json\"");
            ex.sendResponseHeaders(200, jsonBytes.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(jsonBytes); }
        }
    }

    static class SimulateAttackHandler implements HttpHandler {
        final Engine engine;
        SimulateAttackHandler(Engine engine) { this.engine = engine; }

        static final String[] SCRIPT = {
                "Sep 10 14:00:01 edge-fw CEF:0|NetSec|Firewall|1.0|100|PORT_SCAN|Low|src=10.0.0.77 dst=192.168.1.1 proto=TCP dpt=22 flags=SYN",
                "Sep 10 14:00:15 auth-gw sshd[4011]: Failed password for invalid user admin from 10.0.0.77 port 41201 ssh2",
                "Sep 10 14:00:20 auth-gw sshd[4012]: Failed password for invalid user admin from 10.0.0.77 port 41202 ssh2",
                "Sep 10 14:01:05 target-server sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash src=10.0.0.77",
                "Sep 10 14:02:30 edge-proxy CEF:0|NetSec|Proxy|1.0|200|LARGE_TRANSFER|High|src=10.0.0.77 dst=203.0.113.88 category=DATA_EXFIL bytes=52428800"
        };

        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { ex.sendResponseHeaders(405, -1); return; }
            String body = readBody(ex);
            String action = extractJsonField(body, "action");

            if ("stop".equalsIgnoreCase(action)) {
                engine.simRunning = false;
                engine.simCurrentStage = "STOPPED";
                sendJson(ex, 200, Map.of("status", "stopped"));
                return;
            }

            if (engine.simRunning) {
                sendJson(ex, 200, Map.of("status", "already_running", "stage", engine.simCurrentStage));
                return;
            }

            Thread t = new Thread(() -> {
                engine.simRunning = true;
                try {
                    for (int i = 0; i < SCRIPT.length && engine.simRunning; i++) {
                        engine.simCurrentStage = "STAGE " + (i + 1) + "/" + SCRIPT.length;
                        engine.ingest(SCRIPT[i]);
                        try { Thread.sleep(1300); } catch (InterruptedException ignored) {}
                    }
                    if (engine.simRunning) {
                        engine.sealBatch();
                        engine.simCurrentStage = "ATTACK CHAIN COMPLETE & ANCHORED";
                    }
                } finally {
                    engine.simRunning = false;
                }
            });
            t.setDaemon(true);
            t.start();

            sendJson(ex, 200, Map.of("status", "started"));
        }
    }

    static class AnchorHandler implements HttpHandler {
        final Engine engine;
        AnchorHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { ex.sendResponseHeaders(405, -1); return; }
            Batch b = engine.sealBatch();
            if (b == null) { sendJson(ex, 200, Map.of("error", "Buffer empty")); return; }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("batchId", b.batchId);
            m.put("merkleRoot", b.merkleRoot);
            m.put("chainedRoot", b.chainedRoot);
            m.put("leavesAnchored", b.events.size());
            sendJson(ex, 200, m);
        }
    }

    static class ResetHandler implements HttpHandler {
        final Engine engine;
        ResetHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { ex.sendResponseHeaders(405, -1); return; }
            engine.eventsById.clear();
            engine.eventsByHash.clear();
            engine.pendingBuffer.clear();
            engine.mitreTechniqueCounts.clear();
            engine.simRunning = false;
            engine.simCurrentStage = "IDLE";
            sendJson(ex, 200, Map.of("status", "reset_complete", "note", "Ledger remains intact."));
        }
    }

    static class StatusHandler implements HttpHandler {
        final Engine engine;
        StatusHandler(Engine engine) { this.engine = engine; }
        public void handle(HttpExchange ex) throws IOException {
            Map<String, Object> st = new LinkedHashMap<>();
            st.put("totalIngested", engine.eventsById.size());
            st.put("pendingInBatch", engine.pendingBuffer.size());
            st.put("batchesAnchored", engine.sealedBatches.size());
            st.put("chainTip", engine.lastChainedRoot);
            st.put("threatScore", engine.calculateThreatScore());
            st.put("integrityChecksPassed", engine.integrityChecksPassed.get());
            st.put("uniqueFormatsCount", engine.detectedFormats.size());
            st.put("techniquesCount", engine.mitreTechniqueCounts.size());
            st.put("simRunning", engine.simRunning);
            st.put("simStage", engine.simCurrentStage);
            sendJson(ex, 200, st);
        }
    }
}