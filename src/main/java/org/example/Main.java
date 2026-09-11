package org.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {

    // ============================================================
    // Core Domain Models
    // ============================================================
    static class LogEvent {
        String id;
        long timestampMillis;
        String raw;
        String format;
        String sourceIp;
        String destPort;
        String serviceType;
        String masked;
        String templateId;
        String template;
        boolean isNovelTemplate;
        String mitreTacticId;
        String mitreTacticName;
        String mitreTechniqueId;
        String mitreTechniqueName;
        int killChainOrder;
        String leafHash;
        String batchId;
    }

    static class Batch {
        String batchId;
        long timestampMillis;
        List<String> leafHashes = new ArrayList<>();
        String merkleRoot;
        String chainedRoot;
        boolean isSealed;
    }

    static class MerkleProof {
        String leafHash;
        String batchId;
        String rootHash;
        List<String> auditPath = new ArrayList<>();
        List<String> directions = new ArrayList<>();
        boolean isValid;
    }

    // ============================================================
    // Masking & Extraction Engine
    // ============================================================
    static class Masker {
        private static final Pattern IP = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        private static final Pattern UUID_PAT = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
        private static final Pattern HEX = Pattern.compile("0x[0-9a-fA-F]+");
        private static final Pattern NUMBER = Pattern.compile("(?<=\\s|=|^)\\d+(?=\\s|$|,|;|\\.)");
        private static final Pattern PORT = Pattern.compile("(?:dpt|port|dstport)=(\\d+)");

        static String mask(String raw) {
            String s = IP.matcher(raw).replaceAll("<IP>");
            s = UUID_PAT.matcher(s).replaceAll("<UUID>");
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
    // Bounded Drain Template Miner
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
    // MITRE ATT&CK Enterprise Classifier
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

        static class Rule {
            Pattern pattern;
            String tacticId;
            String tacticName;
            String techId;
            String techName;
            int killChainOrder;

            Rule(String regex, String tacId, String tacName, String techId, String techName, int order) {
                this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
                this.tacticId = tacId;
                this.tacticName = tacName;
                this.techId = techId;
                this.techName = techName;
                this.killChainOrder = order;
            }
        }

        static final List<Rule> RULES = List.of(
                new Rule("port_scan|flags=syn|nmap|dpt=22", "TA0043", "Reconnaissance", "T1046", "Network Service Discovery", 1),
                new Rule("failed password|invalid user|authentication failure", "TA0006", "Credential Access", "T1110", "Brute Force", 3),
                new Rule("sudo:.*root.*bash|privilege|user=root", "TA0004", "Privilege Escalation", "T1078", "Valid Accounts", 4),
                new Rule("data_exfil|large_transfer|bytes=\\d{7,}|exfil", "TA0010", "Exfiltration", "T1041", "Exfiltration Over C2", 6),
                new Rule("exploit|remote code|rce", "TA0001", "Initial Access", "T1190", "Exploit Public-Facing App", 2),
                new Rule("powershell|cmd.exe|/bin/sh", "TA0002", "Execution", "T1059", "Command and Scripting Interpreter", 3),
                new Rule("cron|scheduled|registry", "TA0003", "Persistence", "T1053", "Scheduled Task/Job", 4),
                new Rule("clear log|wevtutil|disable fw", "TA0005", "Defense Evasion", "T1070", "Indicator Removal", 5),
                new Rule("net view|arp -a|whoami", "TA0007", "Discovery", "T1087", "Account Discovery", 2),
                new Rule("psexec|wmic|ssh.*admin", "TA0008", "Lateral Movement", "T1021", "Remote Services", 5),
                new Rule("dump|archive|tar -czf", "TA0009", "Collection", "T1560", "Archive Collected Data", 5),
                new Rule("beacon|c2|reverse_shell", "TA0011", "Command and Control", "T1071", "Application Layer Protocol", 6),
                new Rule("ransom|encrypt|wipe|drop database", "TA0040", "Impact", "T1486", "Data Encrypted for Impact", 7)
        );

        static String[] classify(String text) {
            for (Rule r : RULES) {
                if (r.pattern.matcher(text).find()) {
                    return new String[]{r.tacticId, r.tacticName, r.techId, r.techName, String.valueOf(r.killChainOrder)};
                }
            }
            return new String[]{"TA0007", "Discovery", "T1082", "System Info Discovery", "0"};
        }
    }

    // ============================================================
    // Merkle Tree & Ledger Implementation
    // ============================================================
    static class MerkleEngine {
        static String sha256(String input) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] b = md.digest(input.getBytes(StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                for (byte x : b) sb.append(String.format("%02x", x));
                return sb.toString();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        static String buildRoot(List<String> leaves) {
            if (leaves.isEmpty()) return sha256("EMPTY_TREE");
            List<String> current = new ArrayList<>(leaves);
            while (current.size() > 1) {
                List<String> next = new ArrayList<>();
                for (int i = 0; i < current.size(); i += 2) {
                    if (i + 1 < current.size()) {
                        next.add(sha256(current.get(i) + current.get(i + 1)));
                    } else {
                        next.add(current.get(i));
                    }
                }
                current = next;
            }
            return current.get(0);
        }

        static MerkleProof generateProof(List<String> leaves, String targetLeaf) {
            MerkleProof proof = new MerkleProof();
            proof.leafHash = targetLeaf;
            proof.rootHash = buildRoot(leaves);

            int idx = leaves.indexOf(targetLeaf);
            if (idx == -1) {
                proof.isValid = false;
                return proof;
            }

            List<String> current = new ArrayList<>(leaves);
            while (current.size() > 1) {
                List<String> next = new ArrayList<>();
                for (int i = 0; i < current.size(); i += 2) {
                    if (i + 1 < current.size()) {
                        if (i == idx) {
                            proof.auditPath.add(current.get(i + 1));
                            proof.directions.add("R");
                        } else if (i + 1 == idx) {
                            proof.auditPath.add(current.get(i));
                            proof.directions.add("L");
                        }
                        next.add(sha256(current.get(i) + current.get(i + 1)));
                    } else {
                        next.add(current.get(i));
                    }
                }
                idx /= 2;
                current = next;
            }
            proof.isValid = true;
            return proof;
        }

        static boolean verifyProof(String leaf, List<String> path, List<String> dirs, String root) {
            String curr = leaf;
            for (int i = 0; i < path.size(); i++) {
                String sibling = path.get(i);
                String dir = dirs.get(i);
                if ("L".equals(dir)) {
                    curr = sha256(sibling + curr);
                } else {
                    curr = sha256(curr + sibling);
                }
            }
            return curr.equals(root);
        }
    }

    // ============================================================
    // Core Engine Orchestrator
    // ============================================================
    static class Engine {
        final DrainTree drain = new DrainTree();
        final Map<String, LogEvent> eventsById = new ConcurrentHashMap<>();
        final Map<String, LogEvent> eventsByLeaf = new ConcurrentHashMap<>();
        final List<Batch> sealedBatches = new CopyOnWriteArrayList<>();
        final List<LogEvent> currentBatchLeaves = new CopyOnWriteArrayList<>();
        final File ledgerFile = new File("cyberguard_ledger.dat");

        final AtomicInteger eventCounter = new AtomicInteger(0);
        final AtomicInteger batchCounter = new AtomicInteger(0);
        final AtomicInteger simulatedTamperCount = new AtomicInteger(0);

        final AtomicLong lastBenchDurationMs = new AtomicLong(0);
        final AtomicInteger lastBenchEps = new AtomicInteger(0);
        final AtomicInteger lastBenchCount = new AtomicInteger(0);

        String lastChainedRoot = MerkleEngine.sha256("GENESIS_BLOCK_CYBERGUARD");
        final AtomicBoolean simRunning = new AtomicBoolean(false);
        ScheduledExecutorService simScheduler = Executors.newSingleThreadScheduledExecutor();

        static final int BATCH_CAPACITY = 50;
        static final int CORRELATION_WINDOW_SECONDS = 180;

        LogEvent ingest(String raw) {
            LogEvent ev = new LogEvent();
            ev.id = "EV-" + eventCounter.incrementAndGet();
            ev.timestampMillis = System.currentTimeMillis();
            ev.raw = raw;
            ev.format = detectFormat(raw);
            ev.sourceIp = Masker.extractIp(raw);
            ev.destPort = Masker.extractPort(raw);
            ev.serviceType = Masker.extractService(raw);
            ev.masked = Masker.mask(raw);

            Object[] dm = drain.match(ev.masked);
            ev.templateId = (String) dm[0];
            ev.template = (String) dm[1];
            ev.isNovelTemplate = (Boolean) dm[2];

            String[] mc = MitreClassifier.classify(raw + " " + ev.template);
            ev.mitreTacticId = mc[0];
            ev.mitreTacticName = mc[1];
            ev.mitreTechniqueId = mc[2];
            ev.mitreTechniqueName = mc[3];
            ev.killChainOrder = Integer.parseInt(mc[4]);

            ev.leafHash = MerkleEngine.sha256(ev.raw + "|" + ev.timestampMillis + "|" + ev.templateId);

            eventsById.put(ev.id, ev);
            eventsByLeaf.put(ev.leafHash, ev);

            synchronized (currentBatchLeaves) {
                currentBatchLeaves.add(ev);
                if (currentBatchLeaves.size() >= BATCH_CAPACITY) {
                    sealBatch();
                }
            }
            return ev;
        }

        String detectFormat(String raw) {
            if (raw.startsWith("CEF:")) return "CEF";
            if (raw.startsWith("LEEF:")) return "LEEF";
            if (raw.startsWith("{") && raw.endsWith("}")) return "JSON";
            if (raw.startsWith("<") && raw.endsWith(">")) return "XML";
            if (raw.matches("^[a-zA-Z]{3}\\s+\\d+.*")) return "SYSLOG";
            return "CSV";
        }

        synchronized Batch sealBatch() {
            if (currentBatchLeaves.isEmpty()) return null;
            Batch b = new Batch();
            b.batchId = "BATCH-" + batchCounter.incrementAndGet();
            b.timestampMillis = System.currentTimeMillis();

            for (LogEvent e : currentBatchLeaves) {
                e.batchId = b.batchId;
                b.leafHashes.add(e.leafHash);
            }

            b.merkleRoot = MerkleEngine.buildRoot(b.leafHashes);
            b.chainedRoot = MerkleEngine.sha256(lastChainedRoot + "|" + b.merkleRoot);
            lastChainedRoot = b.chainedRoot;
            b.isSealed = true;

            sealedBatches.add(b);
            currentBatchLeaves.clear();

            appendWal(b);
            return b;
        }

        void appendWal(Batch b) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(ledgerFile, true))) {
                pw.println(b.batchId + "|" + b.timestampMillis + "|" + b.merkleRoot + "|" + b.chainedRoot + "|" + b.leafHashes.size());
            } catch (IOException e) {
                System.err.println("WAL append failed: " + e.getMessage());
            }
        }

        int calculateKillChainRiskScore() {
            Set<Integer> hitStages = new HashSet<>();
            for (LogEvent e : eventsById.values()) {
                if (e.killChainOrder > 0) hitStages.add(e.killChainOrder);
            }
            int score = hitStages.size() * 15;
            if (hitStages.contains(1) && hitStages.contains(3)) score += 15;
            if (hitStages.contains(3) && hitStages.contains(4)) score += 15;
            if (hitStages.contains(4) && hitStages.contains(6)) score += 20;
            return Math.min(100, score);
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

        Map<String, Object> runLoadBenchmark(int eventCount) {
            String[] testTemplates = {
                    "CEF:0|NetSec|Firewall|1.0|100|PORT_SCAN|Low|src=192.168.1.50 dst=10.0.0.1 proto=TCP dpt=80",
                    "Sep 10 12:00:00 server sshd[102]: Failed password for root from 192.168.1.50 port 44102 ssh2",
                    "LEEF:2.0|IBM|QRadar|7.3|1001|src=192.168.1.50\tdst=10.0.0.5\tsev=6\tcat=AUTH_FAIL",
                    "{\"timestamp\":\"2026-09-10T12:00:00Z\",\"src\":\"192.168.1.50\",\"service\":\"sudo\",\"action\":\"root_attempt\"}",
                    "<event><src>192.168.1.50</src><dst>203.0.113.10</dst><bytes>1048576</bytes><type>EXFIL</type></event>",
                    "192.168.1.50,10.0.0.1,443,TCP,ALLOW,FLOW_RECORD"
            };

            long startNano = System.nanoTime();
            int batchesBefore = sealedBatches.size();

            for (int i = 0; i < eventCount; i++) {
                String line = testTemplates[i % testTemplates.length] + " iter=" + i;
                ingest(line);
            }
            sealBatch();

            long elapsedMs = (System.nanoTime() - startNano) / 1_000_000;
            if (elapsedMs == 0) elapsedMs = 1;
            int calculatedEps = (int) ((eventCount * 1000L) / elapsedMs);
            int batchesSealed = sealedBatches.size() - batchesBefore;

            lastBenchDurationMs.set(elapsedMs);
            lastBenchEps.set(calculatedEps);
            lastBenchCount.set(eventCount);

            Map<String, Object> res = new LinkedHashMap<>();
            res.put("eventsProcessed", eventCount);
            res.put("elapsedMs", elapsedMs);
            res.put("throughputEps", calculatedEps);
            res.put("batchesCommitted", batchesSealed);
            res.put("avgBatchLatencyMs", (double) elapsedMs / Math.max(1, batchesSealed));
            res.put("chainTip", lastChainedRoot);
            return res;
        }

        Map<String, Object> generateMlTensorPayload() {
            List<LogEvent> events = new ArrayList<>(eventsById.values());
            int start = Math.max(0, events.size() - 50);
            List<LogEvent> workingSet = events.subList(start, events.size());

            Map<String, Integer> idToIndex = new HashMap<>();
            List<List<Double>> xFeatures = new ArrayList<>();

            for (int i = 0; i < workingSet.size(); i++) {
                LogEvent e = workingSet.get(i);
                idToIndex.put(e.id, i);

                double stageNorm = e.killChainOrder / 7.0;
                double portNorm = 0.0;
                try {
                    portNorm = Math.min(1.0, Double.parseDouble(e.destPort) / 65535.0);
                } catch (Exception ignored) {}

                double serviceHash = (Math.abs(e.serviceType.hashCode()) % 100) / 100.0;
                double novelVal = e.isNovelTemplate ? 1.0 : 0.0;
                double entropy = Math.min(1.0, (double) e.template.length() / 80.0);

                xFeatures.add(List.of(stageNorm, portNorm, serviceHash, novelVal, entropy));
            }

            List<Map<String, Object>> edges = buildGraphEdges(workingSet);
            List<Integer> edgeSources = new ArrayList<>();
            List<Integer> edgeTargets = new ArrayList<>();

            for (Map<String, Object> edge : edges) {
                String src = (String) edge.get("source");
                String dst = (String) edge.get("target");
                if (idToIndex.containsKey(src) && idToIndex.containsKey(dst)) {
                    edgeSources.add(idToIndex.get(src));
                    edgeTargets.add(idToIndex.get(dst));
                }
            }

            Map<String, Object> tensor = new LinkedHashMap<>();
            tensor.put("tensorFormat", "PyTorch-Geometric / DGL COO Graph Representation");
            tensor.put("numNodes", workingSet.size());
            tensor.put("numEdges", edgeSources.size());
            tensor.put("featureDimensions", 5);
            tensor.put("featureSchema", List.of("kill_chain_stage", "port_normalized", "service_hash", "template_is_novel", "leaf_entropy"));
            tensor.put("x_node_features", xFeatures);
            tensor.put("edge_index", List.of(edgeSources, edgeTargets));
            tensor.put("generatedAt", Instant.now().toString());
            return tensor;
        }
    }

    // ============================================================
    // HTTP Server & Controllers
    // ============================================================
    public static void main(String[] args) throws IOException {
        Engine engine = new Engine();
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/", new StaticHandler());
        server.createContext("/api/parse", new ParseHandler(engine));
        server.createContext("/api/anchor", new AnchorHandler(engine));
        server.createContext("/api/verify", new VerifyHandler(engine));
        server.createContext("/api/tamper-simulate", new TamperHandler(engine));
        server.createContext("/api/provenance-graph", new GraphHandler(engine));
        server.createContext("/api/mitre-matrix", new MitreHandler(engine));
        server.createContext("/api/status", new StatusHandler(engine));
        server.createContext("/api/simulate-attack", new AttackSimHandler(engine));
        server.createContext("/api/benchmark", new BenchmarkHandler(engine));
        server.createContext("/api/ml-export", new MlExportHandler(engine));
        server.createContext("/api/evidence-bundle", new EvidenceBundleHandler(engine));
        server.createContext("/api/reset", new ResetHandler(engine));

        server.setExecutor(Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()));
        server.start();

        System.out.println("==================================================================");
        System.out.println("  LogAnchor-X Core Substrate Online");
        System.out.println("  Air-Gapped Sovereign Ingestion Active");
        System.out.println("  Console: http://localhost:" + port);
        System.out.println("==================================================================");
    }

    static void sendJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    static String readBody(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    // Static Resource
    static class StaticHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            try (InputStream is = getClass().getResourceAsStream("/index.html")) {
                if (is == null) {
                    byte[] err = "<html><body><h1>index.html not found</h1></body></html>".getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(404, err.length);
                    ex.getResponseBody().write(err);
                    return;
                }
                byte[] html = is.readAllBytes();
                ex.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
                ex.sendResponseHeaders(200, html.length);
                try (OutputStream os = ex.getResponseBody()) { os.write(html); }
            }
        }
    }

    // Parse Handler
    static class ParseHandler implements HttpHandler {
        final Engine engine;
        ParseHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { sendJson(ex, 405, "{}"); return; }
            String b = readBody(ex);
            String log = "";
            int idx = b.indexOf("\"log\":");
            if (idx != -1) {
                int start = b.indexOf("\"", idx + 6) + 1;
                int end = b.lastIndexOf("\"");
                if (start > 0 && end > start) log = b.substring(start, end);
            }
            if (log.isEmpty()) log = b;

            LogEvent ev = engine.ingest(log);
            sendJson(ex, 200, String.format(
                    "{\"id\":\"%s\",\"leafHash\":\"%s\",\"format\":\"%s\",\"templateId\":\"%s\",\"template\":\"%s\",\"mitreTactic\":\"%s\",\"mitreTechnique\":\"%s\"}",
                    ev.id, ev.leafHash, ev.format, ev.templateId, escape(ev.template), ev.mitreTacticName, ev.mitreTechniqueName
            ));
        }
    }

    // Benchmark Handler
    static class BenchmarkHandler implements HttpHandler {
        final Engine engine;
        BenchmarkHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            int count = 5000;
            String b = readBody(ex);
            if (b.contains("\"count\":")) {
                try {
                    String num = b.replaceAll("[^0-9]", "");
                    if (!num.isEmpty()) count = Integer.parseInt(num);
                } catch (Exception ignored) {}
            }
            Map<String, Object> res = engine.runLoadBenchmark(count);
            sendJson(ex, 200, toJson(res));
        }
    }

    // ML Tensor Export
    static class MlExportHandler implements HttpHandler {
        final Engine engine;
        MlExportHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            Map<String, Object> payload = engine.generateMlTensorPayload();
            sendJson(ex, 200, toJson(payload));
        }
    }

    // Evidence Bundle Exporter
    static class EvidenceBundleHandler implements HttpHandler {
        final Engine engine;
        EvidenceBundleHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            Map<String, Object> bundle = new LinkedHashMap<>();
            bundle.put("bundleType", "COURT_ADMISSIBLE_FORENSIC_LEDGER");
            bundle.put("organization", "NTRO_CYBER_DEFENSE_SUBSTRATE");
            bundle.put("exportedAt", Instant.now().toString());
            bundle.put("totalBatches", engine.sealedBatches.size());
            bundle.put("latestChainedRoot", engine.lastChainedRoot);

            List<Map<String, Object>> batchList = new ArrayList<>();
            for (Batch b : engine.sealedBatches) {
                Map<String, Object> bm = new LinkedHashMap<>();
                bm.put("batchId", b.batchId);
                bm.put("timestamp", b.timestampMillis);
                bm.put("merkleRoot", b.merkleRoot);
                bm.put("chainedRoot", b.chainedRoot);
                bm.put("leafCount", b.leafHashes.size());
                batchList.add(bm);
            }
            bundle.put("batches", batchList);
            sendJson(ex, 200, toJson(bundle));
        }
    }

    // Anchor Handler
    static class AnchorHandler implements HttpHandler {
        final Engine engine;
        AnchorHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            Batch b = engine.sealBatch();
            if (b == null) {
                sendJson(ex, 200, "{\"status\":\"NOOP\",\"message\":\"Batch queue is empty\"}");
                return;
            }
            sendJson(ex, 200, String.format(
                    "{\"batchId\":\"%s\",\"merkleRoot\":\"%s\",\"chainedRoot\":\"%s\",\"leavesAnchored\":%d}",
                    b.batchId, b.merkleRoot, b.chainedRoot, b.leafHashes.size()
            ));
        }
    }

    // Verify Handler
    static class VerifyHandler implements HttpHandler {
        final Engine engine;
        VerifyHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            String query = ex.getRequestURI().getQuery();
            String targetLeaf = "";
            if (query != null && query.contains("leafHash=")) {
                targetLeaf = query.split("leafHash=")[1].split("&")[0];
            }

            Batch foundBatch = null;
            for (Batch b : engine.sealedBatches) {
                if (b.leafHashes.contains(targetLeaf)) {
                    foundBatch = b;
                    break;
                }
            }

            if (foundBatch == null) {
                sendJson(ex, 200, "{\"valid\":false,\"message\":\"Leaf not found in any sealed batch\"}");
                return;
            }

            MerkleProof p = MerkleEngine.generateProof(foundBatch.leafHashes, targetLeaf);
            boolean verified = MerkleEngine.verifyProof(targetLeaf, p.auditPath, p.directions, foundBatch.merkleRoot);

            sendJson(ex, 200, String.format(
                    "{\"valid\":%b,\"batchId\":\"%s\",\"recomputedRoot\":\"%s\",\"anchoredRoot\":\"%s\",\"message\":\"%s\"}",
                    verified, foundBatch.batchId, p.rootHash, foundBatch.merkleRoot,
                    verified ? "O(log N) Cryptographic Audit Validated" : "Tampering Detected"
            ));
        }
    }

    // Tamper Simulator Handler
    static class TamperHandler implements HttpHandler {
        final Engine engine;
        TamperHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            String b = readBody(ex);
            String leaf = "";
            int idx = b.indexOf("\"leafHash\":");
            if (idx != -1) {
                int start = b.indexOf("\"", idx + 11) + 1;
                int end = b.indexOf("\"", start);
                if (start > 0 && end > start) leaf = b.substring(start, end);
            }

            Batch foundBatch = null;
            for (Batch batch : engine.sealedBatches) {
                if (batch.leafHashes.contains(leaf)) {
                    foundBatch = batch;
                    break;
                }
            }

            if (foundBatch == null) {
                sendJson(ex, 200, "{\"valid\":false,\"message\":\"Target leaf not in sealed batch to tamper\"}");
                return;
            }

            int leafIdx = foundBatch.leafHashes.indexOf(leaf);
            String tampered = MerkleEngine.sha256(leaf + "_CORRUPTED_BY_ATTACKER");
            foundBatch.leafHashes.set(leafIdx, tampered);
            engine.simulatedTamperCount.incrementAndGet();

            String newRoot = MerkleEngine.buildRoot(foundBatch.leafHashes);

            sendJson(ex, 200, String.format(
                    "{\"valid\":false,\"batchId\":\"%s\",\"recomputedRoot\":\"%s\",\"anchoredRoot\":\"%s\",\"message\":\"CRITICAL: Sibling Path Hash Mismatch!\"}",
                    foundBatch.batchId, newRoot, foundBatch.merkleRoot
            ));
        }
    }

    // Provenance Graph Handler
    static class GraphHandler implements HttpHandler {
        final Engine engine;
        GraphHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            List<LogEvent> events = new ArrayList<>(engine.eventsById.values());
            int start = Math.max(0, events.size() - 40);
            List<LogEvent> workingSet = events.subList(start, events.size());

            StringBuilder sb = new StringBuilder();
            sb.append("{\"nodes\":[");
            for (int i = 0; i < workingSet.size(); i++) {
                LogEvent ev = workingSet.get(i);
                if (i > 0) sb.append(",");
                sb.append(String.format(
                        "{\"id\":\"%s\",\"raw\":\"%s\",\"sourceIp\":\"%s\",\"destPort\":\"%s\",\"service\":\"%s\",\"mitreId\":\"%s\",\"mitreTechnique\":\"%s\",\"stage\":%d,\"leafHash\":\"%s\"}",
                        ev.id, escape(ev.raw), ev.sourceIp, ev.destPort, ev.serviceType, ev.mitreTechniqueId, escape(ev.mitreTechniqueName), ev.killChainOrder, ev.leafHash
                ));
            }
            sb.append("],\"edges\":[");
            List<Map<String, Object>> edges = engine.buildGraphEdges(workingSet);
            for (int i = 0; i < edges.size(); i++) {
                if (i > 0) sb.append(",");
                Map<String, Object> edge = edges.get(i);
                sb.append(String.format("{\"source\":\"%s\",\"target\":\"%s\",\"confidence\":\"%s\",\"timeGapSec\":%s}",
                        edge.get("source"), edge.get("target"), edge.get("confidence"), edge.get("timeGapSec")));
            }
            sb.append("]}");
            sendJson(ex, 200, sb.toString());
        }
    }

    // MITRE ATT&CK Matrix Matrix Handler
    static class MitreHandler implements HttpHandler {
        final Engine engine;
        MitreHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            Map<String, AtomicInteger> techniqueCounts = new HashMap<>();
            for (LogEvent ev : engine.eventsById.values()) {
                techniqueCounts.computeIfAbsent(ev.mitreTechniqueId, k -> new AtomicInteger(0)).incrementAndGet();
            }

            StringBuilder sb = new StringBuilder("{\"tactics\":[");
            for (int i = 0; i < MitreClassifier.MITRE_14_TACTICS.size(); i++) {
                if (i > 0) sb.append(",");
                String[] tac = MitreClassifier.MITRE_14_TACTICS.get(i);
                sb.append(String.format("{\"id\":\"%s\",\"name\":\"%s\",\"techniques\":[", tac[0], tac[1]));

                List<MitreClassifier.Rule> matchingRules = new ArrayList<>();
                for (MitreClassifier.Rule r : MitreClassifier.RULES) {
                    if (r.tacticId.equals(tac[0])) matchingRules.add(r);
                }

                for (int j = 0; j < matchingRules.size(); j++) {
                    if (j > 0) sb.append(",");
                    MitreClassifier.Rule r = matchingRules.get(j);
                    int count = techniqueCounts.containsKey(r.techId) ? techniqueCounts.get(r.techId).get() : 0;
                    sb.append(String.format("{\"id\":\"%s\",\"name\":\"%s\",\"count\":%d}", r.techId, r.techName, count));
                }
                sb.append("]}");
            }
            sb.append("]}");
            sendJson(ex, 200, sb.toString());
        }
    }

    // Status Handler
    static class StatusHandler implements HttpHandler {
        final Engine engine;
        StatusHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            int ingested = engine.eventCounter.get();
            int sealed = engine.sealedBatches.size();
            int detections = 0;
            for (LogEvent ev : engine.eventsById.values()) {
                if (ev.killChainOrder > 0) detections++;
            }
            int integrityAudits = engine.simulatedTamperCount.get();
            int threatScore = engine.calculateKillChainRiskScore();

            sendJson(ex, 200, String.format(
                    "{\"ingested\":%d,\"sealedBatches\":%d,\"adaptersActive\":6,\"detections\":%d,\"validations\":%d,\"threatScore\":%d,\"lastChainedRoot\":\"%s\",\"benchEps\":%d,\"simRunning\":%b}",
                    ingested, sealed, detections, integrityAudits, threatScore, engine.lastChainedRoot, engine.lastBenchEps.get(), engine.simRunning.get()
            ));
        }
    }

    // Attack Simulator
    static class AttackSimHandler implements HttpHandler {
        final Engine engine;
        AttackSimHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            boolean active = engine.simRunning.get();
            if (active) {
                engine.simRunning.set(false);
                sendJson(ex, 200, "{\"status\":\"HALTED\"}");
            } else {
                engine.simRunning.set(true);
                runAttackScenario();
                sendJson(ex, 200, "{\"status\":\"STARTED\"}");
            }
        }

        void runAttackScenario() {
            String[] scenario = {
                    "Sep 10 14:00:01 edge-fw CEF:0|NetSec|Firewall|1.0|100|PORT_SCAN|Low|src=10.0.0.77 dst=192.168.1.1 proto=TCP dpt=22 flags=SYN",
                    "Sep 10 14:00:15 auth-gw sshd[4011]: Failed password for invalid user admin from 10.0.0.77 port 41201 ssh2",
                    "Sep 10 14:01:05 target-server sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash src=10.0.0.77",
                    "Sep 10 14:02:30 edge-proxy CEF:0|NetSec|Proxy|1.0|200|LARGE_TRANSFER|High|src=10.0.0.77 dst=203.0.113.88 category=DATA_EXFIL bytes=52428800"
            };

            ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor();
            for (int i = 0; i < scenario.length; i++) {
                final int idx = i;
                exec.schedule(() -> {
                    if (engine.simRunning.get()) {
                        engine.ingest(scenario[idx]);
                    }
                }, i * 1200L, TimeUnit.MILLISECONDS);
            }
            exec.schedule(() -> {
                engine.sealBatch();
                engine.simRunning.set(false);
            }, (scenario.length * 1200L) + 500L, TimeUnit.MILLISECONDS);
        }
    }

    // Reset Handler
    static class ResetHandler implements HttpHandler {
        final Engine engine;
        ResetHandler(Engine e) { this.engine = e; }
        @Override
        public void handle(HttpExchange ex) throws IOException {
            engine.eventsById.clear();
            engine.eventsByLeaf.clear();
            engine.currentBatchLeaves.clear();
            engine.simRunning.set(false);
            sendJson(ex, 200, "{\"status\":\"RESET_COMPLETE\"}");
        }
    }

    // Helper Serializers
    static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    static String toJson(Object obj) {
        if (obj instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\"").append(e.getKey()).append("\":").append(toJson(e.getValue()));
            }
            sb.append("}");
            return sb.toString();
        } else if (obj instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(toJson(list.get(i)));
            }
            sb.append("]");
            return sb.toString();
        } else if (obj instanceof String str) {
            return "\"" + escape(str) + "\"";
        } else {
            return String.valueOf(obj);
        }
    }
}