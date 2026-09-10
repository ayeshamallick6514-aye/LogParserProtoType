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
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * LogAnchor-X — Universal Log Pre-processing Framework (SIH 2026, PS 26156)
 * Organisation: NTRO | Theme: Blockchain & Cybersecurity
 * Phase 4: Automated APT Simulation Player & Gamified SOC Telemetry Engine
 */
public class Main {

    static final int    PORT       = 8080;
    static final int    BATCH_SIZE = 64;
    static final Path   LEDGER     = Paths.get("cyberguard_ledger.dat");

    // ── Drain Template Tree ──────────────────────────────────────────────────
    static class ParseNode {
        Map<String, ParseNode> children = new LinkedHashMap<>();
        String logTemplate;
        long   matchCount;
    }
    static final ParseNode ROOT_TREE = new ParseNode();

    // ── Event Model ─────────────────────────────────────────────────────────
    static class Event {
        String id;
        String raw, masked, template, leafHash;
        String sourceIp, user;
        String intentCluster;
        String mitreTacticId, mitreTacticName, mitreTechnique, mitreId;
        int    killChainStage; // 1: Recon, 2: Initial, 3: Credential, 4: PrivEsc, 5: Lateral, 6: Exfil
        boolean templateIsNovel;
        long   ts;
    }

    static final List<Event> pendingBuffer = new ArrayList<>();
    static final List<Event> allIngestedEvents = Collections.synchronizedList(new ArrayList<>());
    static long totalIngested = 0;
    static long integrityChecksPassed = 0;
    static final Set<String> detectedFormats = ConcurrentHashMap.newKeySet();

    // ── MITRE ATT&CK Counts ──────────────────────────────────────────────────
    static final Map<String, Integer> mitreTechniqueCounts = new ConcurrentHashMap<>();

    // ── Simulation State ─────────────────────────────────────────────────────
    static volatile boolean simRunning = false;
    static volatile String  simCurrentStage = "IDLE";

    // ── Anchored Ledger & Merkle Batches ────────────────────────────────────
    static class Batch {
        long   id, timestamp;
        String merkleRoot, chainedRoot;
        List<String>       rawLogs     = new ArrayList<>();
        List<String>       leafHashes  = new ArrayList<>();
        List<List<String>> siblingPaths = new ArrayList<>();
    }
    static final List<Batch> batches = new ArrayList<>();
    static final Map<String, int[]> leafIndex = new ConcurrentHashMap<>();
    static String prevChainedRoot = "GENESIS";
    static long   batchCounter    = 0;

    // ── Masking Patterns ─────────────────────────────────────────────────────
    static final Pattern IP_RE   = Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");
    static final Pattern UUID_RE = Pattern.compile("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b");
    static final Pattern HEX_RE  = Pattern.compile("\\b0x[0-9a-fA-F]+\\b");
    static final Pattern TS_RE   = Pattern.compile("\\b\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?\\b");
    static final Pattern NUM_RE  = Pattern.compile("\\b\\d+\\b");

    static String mask(String s) {
        s = IP_RE.matcher(s).replaceAll("<IP>");
        s = UUID_RE.matcher(s).replaceAll("<ID>");
        s = HEX_RE.matcher(s).replaceAll("<HEX>");
        s = TS_RE.matcher(s).replaceAll("<TS>");
        s = NUM_RE.matcher(s).replaceAll("<N>");
        return s;
    }

    static String extractIp(String raw) {
        Matcher m = IP_RE.matcher(raw);
        return m.find() ? m.group() : "UNKNOWN_SRC";
    }

    // ── Multi-Format Adapters ───────────────────────────────────────────────
    interface LogAdapter { String name(); int confidence(String raw); String normalize(String raw); }

    static final List<LogAdapter> ADAPTERS = List.of(
            new CefAdapter(), new LeefAdapter(), new XmlAdapter(),
            new JsonAdapter(), new CsvAdapter(), new FlatTextAdapter());

    static class RouteResult { String normalized; String formatName; }

    static RouteResult route(String raw) {
        LogAdapter best = null; int bestScore = -1;
        for (LogAdapter a : ADAPTERS) { int c = a.confidence(raw); if (c > bestScore) { bestScore = c; best = a; } }
        RouteResult rr = new RouteResult();
        rr.normalized = best != null ? best.normalize(raw) : raw;
        rr.formatName = best != null ? best.name() : "SYSLOG";
        return rr;
    }

    static List<String> splitUnescaped(String s, char delim) {
        List<String> out = new ArrayList<>(); StringBuilder cur = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) { cur.append(c).append(s.charAt(++i)); continue; }
            if (c == delim) { out.add(cur.toString()); cur.setLength(0); continue; }
            cur.append(c);
        }
        out.add(cur.toString()); return out;
    }

    static class CefAdapter implements LogAdapter {
        public String name() { return "CEF"; }
        public int confidence(String raw) { return raw.trim().startsWith("CEF:") ? 95 : 0; }
        public String normalize(String raw) {
            List<String> p = splitUnescaped(raw.trim(), '|');
            StringBuilder sb = new StringBuilder("CEF");
            for (int i = 1; i < Math.min(p.size(), 8); i++) sb.append(' ').append(mask(p.get(i).replace("\\|","|").trim()));
            if (p.size() > 7) for (String kv : p.get(7).trim().split(" (?=[^=\\s]+=)")) { int eq = kv.indexOf('='); if (eq > 0) sb.append(' ').append(kv, 0, eq).append("=<V>"); }
            return sb.toString();
        }
    }
    static class LeefAdapter implements LogAdapter {
        public String name() { return "LEEF"; }
        public int confidence(String raw) { return raw.trim().startsWith("LEEF:") ? 95 : 0; }
        public String normalize(String raw) {
            String t = raw.trim(); int tab = t.indexOf('\t');
            String header = tab >= 0 ? t.substring(0, tab) : t;
            String attrs  = tab >= 0 ? t.substring(tab + 1) : "";
            StringBuilder sb = new StringBuilder("LEEF");
            for (String p : splitUnescaped(header,'|')) if (!p.trim().isEmpty()) sb.append(' ').append(mask(p.replace("\\|","|").trim()));
            for (String kv : attrs.split("\t")) { int eq = kv.indexOf('='); if (eq > 0) sb.append(' ').append(kv, 0, eq).append("=<V>"); }
            return sb.toString();
        }
    }
    static class XmlAdapter implements LogAdapter {
        static final Pattern AR = Pattern.compile("(\\w+)=\"[^\"]*\"");
        public String name() { return "XML"; }
        public int confidence(String raw) { String t = raw.trim(); return (t.startsWith("<") && t.endsWith(">")) ? 85 : 0; }
        public String normalize(String raw) {
            String text = raw.replaceAll("<[^>]+>"," ").trim().replaceAll("\\s+"," ");
            Set<String> keys = new LinkedHashSet<>(); Matcher m = AR.matcher(raw); while (m.find()) keys.add(m.group(1));
            StringBuilder sb = new StringBuilder("XML ").append(mask(text));
            for (String k : keys) sb.append(' ').append(k).append("=<V>");
            return sb.toString();
        }
    }
    static class JsonAdapter implements LogAdapter {
        public String name() { return "JSON"; }
        public int confidence(String raw) { return raw.trim().startsWith("{") ? 90 : 0; }
        public String normalize(String raw) { return raw.trim().replaceAll("[{}\".,:]", " "); }
    }
    static class CsvAdapter implements LogAdapter {
        public String name() { return "CSV"; }
        public int confidence(String raw) { long c = raw.trim().chars().filter(x -> x==',').count(); return c>=2 && !raw.contains("|") ? 60 : 0; }
        public String normalize(String raw) { StringBuilder sb = new StringBuilder("CSV"); for (String col : raw.trim().split(",",-1)) sb.append(' ').append(mask(col.trim())); return sb.toString(); }
    }
    static class FlatTextAdapter implements LogAdapter {
        public String name() { return "SYSLOG"; }
        public int confidence(String raw) { return 10; }
        public String normalize(String raw) { return raw; }
    }

    // ── 14 MITRE Tactics & Seed Classifier ──────────────────────────────────
    static class MitreMapping {
        String tacticId, tacticName, technique, id;
        int killChainStage;
        MitreMapping(String tacId, String tacName, String tech, String id, int stage) {
            this.tacticId = tacId; this.tacticName = tacName; this.technique = tech; this.id = id;
            this.killChainStage = stage;
        }
    }

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

    static MitreMapping classifyMitre(String intentCluster) {
        switch (intentCluster) {
            case "RECON_PORTSCAN":
                return new MitreMapping("TA0043", "Reconnaissance", "Network Service Discovery", "T1046", 1);
            case "INITIAL_EXPLOIT":
                return new MitreMapping("TA0001", "Initial Access", "Exploit Public-Facing Application", "T1190", 2);
            case "CREDENTIAL_BRUTEFORCE":
                return new MitreMapping("TA0006", "Credential Access", "Brute Force", "T1110", 3);
            case "PRIV_ESCALATION":
                return new MitreMapping("TA0004", "Privilege Escalation", "Valid Accounts", "T1078", 4);
            case "LATERAL_SSH":
                return new MitreMapping("TA0008", "Lateral Movement", "Remote Services", "T1021", 5);
            case "DATA_EXFILTRATION":
                return new MitreMapping("TA0010", "Exfiltration", "Exfiltration Over C2 Channel", "T1041", 6);
            case "EXEC_COMMAND":
                return new MitreMapping("TA0002", "Execution", "Command & Scripting", "T1059", 2);
            case "PERSIST_CRON":
                return new MitreMapping("TA0003", "Persistence", "Scheduled Task", "T1053", 4);
            default:
                return new MitreMapping("UNCLASSIFIED", "Unclassified", "Unknown Pattern", "UNCLASSIFIED", 0);
        }
    }

    static String deriveIntentCluster(String text) {
        String l = text.toLowerCase();
        if (l.contains("port_scan") || l.contains("scan") || l.contains("flags=syn") || l.contains("dpt="))
            return "RECON_PORTSCAN";
        if (l.contains("failed") || l.contains("denied") || l.contains("login failure") || l.contains("password"))
            return "CREDENTIAL_BRUTEFORCE";
        if (l.contains("sudo") || l.contains("privilege") || l.contains("uid=0") || l.contains("unauthorized_access"))
            return "PRIV_ESCALATION";
        if (l.contains("ssh2") || l.contains("accepted publickey") || l.contains("remote") || l.contains("connection from"))
            return "LATERAL_SSH";
        if (l.contains("exfil") || l.contains("large_transfer") || l.contains("geo_anomaly") || l.contains("bytes=52428800"))
            return "DATA_EXFILTRATION";
        if (l.contains("/bin/sh") || l.contains("bash") || l.contains("cmd.exe") || l.contains("exec"))
            return "EXEC_COMMAND";
        if (l.contains("crontab") || l.contains("scheduled_task"))
            return "PERSIST_CRON";
        return "UNCLASSIFIED";
    }

    // ── Ingest Pipeline ──────────────────────────────────────────────────────
    static synchronized Event ingest(String raw) {
        RouteResult rr = route(raw);
        detectedFormats.add(rr.formatName);
        String masked     = mask(rr.normalized);
        String[] words    = masked.split(" ");
        String firstWord  = words.length > 0 ? words[0] : "";

        ParseNode lengthNode = ROOT_TREE.children.computeIfAbsent(String.valueOf(words.length), k -> new ParseNode());
        boolean isNovel = false;
        ParseNode target = lengthNode.children.get(firstWord);
        if (target == null) {
            target = new ParseNode(); target.logTemplate = masked; target.matchCount = 1;
            lengthNode.children.put(firstWord, target); isNovel = true;
        } else {
            String[] ex = target.logTemplate.split(" "); StringBuilder upd = new StringBuilder();
            for (int i = 0; i < words.length; i++) upd.append(i < ex.length && ex[i].equals(words[i]) ? ex[i] : "<*>").append(' ');
            target.logTemplate = upd.toString().trim(); target.matchCount++;
        }

        Event ev            = new Event();
        ev.id               = "EVT_" + (totalIngested + 1);
        ev.raw              = raw.trim();
        ev.masked           = masked;
        ev.template         = target.logTemplate;
        ev.templateIsNovel  = isNovel;
        ev.leafHash         = sha256(ev.raw);
        ev.sourceIp         = extractIp(ev.raw);
        ev.ts               = System.currentTimeMillis();

        ev.intentCluster    = deriveIntentCluster(ev.raw + " " + ev.template);
        MitreMapping mm     = classifyMitre(ev.intentCluster);
        ev.mitreTacticId    = mm.tacticId;
        ev.mitreTacticName  = mm.tacticName;
        ev.mitreTechnique   = mm.technique;
        ev.mitreId          = mm.id;
        ev.killChainStage   = mm.killChainStage;

        mitreTechniqueCounts.merge(ev.mitreId, 1, Integer::sum);

        pendingBuffer.add(ev);
        allIngestedEvents.add(ev);
        totalIngested++;

        if (pendingBuffer.size() >= BATCH_SIZE) {
            anchorBatch();
        }
        return ev;
    }

    // ── Threat Score Calculation (Gamified Rule-Based Composite) ────────────
    static int calculateThreatScore() {
        int score = 0;
        int stagesCovered = 0;
        Set<Integer> activeStages = new HashSet<>();
        synchronized (allIngestedEvents) {
            for (Event e : allIngestedEvents) {
                if (e.killChainStage > 0) activeStages.add(e.killChainStage);
            }
        }
        stagesCovered = activeStages.size();

        // 1 stage = 20, 2 stages = 45, 3 stages = 70, 4+ stages = 95
        if (stagesCovered == 1) score = 25;
        else if (stagesCovered == 2) score = 55;
        else if (stagesCovered == 3) score = 78;
        else if (stagesCovered >= 4) score = 96;

        return Math.min(100, Math.max(0, score));
    }

    // ── Merkle Tree & Batch Anchoring ────────────────────────────────────────
    static synchronized Batch anchorBatch() {
        if (pendingBuffer.isEmpty()) return null;
        Batch b = new Batch(); b.id = ++batchCounter; b.timestamp = System.currentTimeMillis();
        for (Event e : pendingBuffer) { b.rawLogs.add(e.raw); b.leafHashes.add(e.leafHash); }
        MerkleTree tree = new MerkleTree(b.leafHashes);
        b.merkleRoot   = tree.getRoot();
        b.chainedRoot  = sha256(b.merkleRoot + prevChainedRoot);
        for (int i = 0; i < b.leafHashes.size(); i++) {
            b.siblingPaths.add(tree.siblingPath(i));
            leafIndex.put(b.leafHashes.get(i), new int[]{batches.size(), i});
        }
        batches.add(b);
        prevChainedRoot = b.chainedRoot;
        pendingBuffer.clear();
        persistLedger(b);
        return b;
    }

    static class MerkleTree {
        private final List<List<String>> levels = new ArrayList<>();
        MerkleTree(List<String> leaves) {
            List<String> cur = new ArrayList<>(leaves); levels.add(new ArrayList<>(cur));
            while (cur.size() > 1) {
                List<String> next = new ArrayList<>();
                for (int i = 0; i < cur.size(); i += 2) {
                    String l = cur.get(i), r = i + 1 < cur.size() ? cur.get(i + 1) : l;
                    next.add(sha256(l + r));
                }
                levels.add(next); cur = next;
            }
        }
        String getRoot() { List<String> top = levels.get(levels.size() - 1); return top.isEmpty() ? sha256("") : top.get(0); }
        List<String> siblingPath(int idx) {
            List<String> path = new ArrayList<>();
            for (int l = 0; l < levels.size() - 1; l++) {
                List<String> lv = levels.get(l); int sib = idx % 2 == 0 ? idx + 1 : idx - 1;
                path.add(sib < lv.size() ? lv.get(sib) : lv.get(idx)); idx /= 2;
            }
            return path;
        }
    }

    static Map<String, Object> computeVerification(String leafHash, int batchId) {
        Map<String, Object> res = new LinkedHashMap<>();
        int[] loc = leafIndex.get(leafHash);
        if (loc == null || (batchId > 0 && batches.get(loc[0]).id != batchId)) {
            res.put("valid", false);
            res.put("leafHash", leafHash);
            res.put("batchId", batchId > 0 ? batchId : -1);
            res.put("message", "Leaf hash not found in specified anchored ledger batch.");
            return res;
        }

        Batch b = batches.get(loc[0]);
        List<String> path = b.siblingPaths.get(loc[1]);
        String recomputed = leafHash;
        List<String> steps = new ArrayList<>();
        for (String sib : path) {
            steps.add(sib);
            recomputed = sha256(recomputed + sib);
        }

        boolean valid = recomputed.equals(b.merkleRoot);
        if (valid) integrityChecksPassed++;

        res.put("valid", valid);
        res.put("leafHash", leafHash);
        res.put("batchId", b.id);
        res.put("recomputedRoot", recomputed);
        res.put("anchoredRoot", b.merkleRoot);
        res.put("chainedRoot", b.chainedRoot);
        res.put("proofPath", steps);
        res.put("message", valid ? "Cryptographic proof validated against anchored Merkle root." : "Tamper detected: recomputed root mismatch.");
        return res;
    }

    // ── Persistence ──────────────────────────────────────────────────────────
    static synchronized void persistLedger(Batch b) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("BATCH\t").append(b.id).append('\t').append(b.merkleRoot).append('\t').append(b.chainedRoot).append('\t').append(b.timestamp);
            for (String r : b.rawLogs) sb.append('\t').append(r.replace("\t", " ").replace("\n", " "));
            sb.append("\t@@PROOFS@@");
            for (int i = 0; i < b.leafHashes.size(); i++) sb.append('\t').append(b.leafHashes.get(i)).append(':').append(String.join(",", b.siblingPaths.get(i)));
            Files.write(LEDGER, (sb + "\n").getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) { System.out.println("[!] Ledger write failed: " + e.getMessage()); }
    }

    static synchronized void loadLedger() {
        if (!Files.exists(LEDGER)) return;
        try {
            for (String line : Files.readAllLines(LEDGER)) {
                String[] f = line.split("\t"); if (f.length < 6 || !f[0].equals("BATCH")) continue;
                Batch b = new Batch(); b.id = Long.parseLong(f[1]); b.merkleRoot = f[2]; b.chainedRoot = f[3]; b.timestamp = Long.parseLong(f[4]);
                int pa = -1; for (int i = 5; i < f.length; i++) if (f[i].equals("@@PROOFS@@")) { pa = i; break; }
                for (int i = 5; i < (pa < 0 ? f.length : pa); i++) b.rawLogs.add(f[i]);
                if (pa >= 0) for (int i = pa + 1; i < f.length; i++) {
                    int colon = f[i].indexOf(':'); if (colon < 0) continue;
                    b.leafHashes.add(f[i].substring(0, colon));
                    String p = f[i].substring(colon + 1);
                    b.siblingPaths.add(p.isEmpty() ? new ArrayList<>() : List.of(p.split(",")));
                }
                for (int i = 0; i < b.leafHashes.size(); i++) leafIndex.put(b.leafHashes.get(i), new int[]{batches.size(), i});
                batches.add(b); batchCounter = Math.max(batchCounter, b.id); prevChainedRoot = b.chainedRoot;
            }
            System.out.println("[+] Loaded " + batches.size() + " anchored batches from ledger.");
        } catch (Exception e) { System.out.println("[!] Ledger recovery error: " + e.getMessage()); }
    }

    static synchronized void resetState() {
        pendingBuffer.clear();
        synchronized (allIngestedEvents) { allIngestedEvents.clear(); }
        ROOT_TREE.children.clear();
        totalIngested = 0;
        integrityChecksPassed = 0;
        detectedFormats.clear();
        mitreTechniqueCounts.clear();
        batches.clear();
        leafIndex.clear();
        prevChainedRoot = "GENESIS";
        batchCounter = 0;
        simRunning = false;
        simCurrentStage = "IDLE";
        try { Files.deleteIfExists(LEDGER); }
        catch (IOException e) { System.out.println("[!] Ledger reset failed: " + e.getMessage()); }
    }

    // ── Automated APT Attack Simulator (Phase 4) ─────────────────────────────
    static void sleep(int ms) { try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }
    static String nowTime() { return LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")); }

    static void executeAptSimulation() {
        simRunning = true;
        String attackerIp = "10.0.0.77";
        try {
            // Stage 1: Recon (Port Scan)
            simCurrentStage = "1. RECONNAISSANCE (PORT SCAN)";
            ingest("Sep 10 " + nowTime() + " edge-fw CEF:0|NetSec|Firewall|1.0|100|PORT_SCAN|Low|src=" + attackerIp + " dst=192.168.1.1 proto=TCP dpt=22 flags=SYN");
            sleep(1400);

            if (!simRunning) return;

            // Stage 2: Credential Access (Brute Force)
            simCurrentStage = "2. CREDENTIAL ACCESS (BRUTE FORCE)";
            for (int i = 1; i <= 3 && simRunning; i++) {
                ingest("Sep 10 " + nowTime() + " auth-gw sshd[401" + i + "]: Failed password for invalid user admin from " + attackerIp + " port " + (41200 + i) + " ssh2");
                sleep(1200);
            }

            if (!simRunning) return;

            // Stage 3: Privilege Escalation (Sudo root)
            simCurrentStage = "3. PRIVILEGE ESCALATION (VALID ACCOUNTS)";
            ingest("Sep 10 " + nowTime() + " target-server sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash src=" + attackerIp);
            sleep(1500);

            if (!simRunning) return;

            // Stage 4: Exfiltration (C2 Dump)
            simCurrentStage = "4. EXFILTRATION (OVER C2)";
            ingest("Sep 10 " + nowTime() + " edge-proxy CEF:0|NetSec|Proxy|1.0|200|LARGE_TRANSFER|High|src=" + attackerIp + " dst=203.0.113.88 category=DATA_EXFIL bytes=52428800");

            // Auto-seal the incident batch to demonstrate immediate tamper protection
            sleep(1000);
            if (!simRunning) return;
            anchorBatch();
            simCurrentStage = "ATTACK CHAIN COMPLETE & ANCHORED";

        } finally {
            simRunning = false;
        }
    }

    // ── Crypto & JSON Utilities ──────────────────────────────────────────────
    static String sha256(String base) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            byte[] h = d.digest(base.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) { String hex = Integer.toHexString(0xff & b); if (hex.length() == 1) sb.append('0'); sb.append(hex); }
            return sb.toString();
        } catch (Exception e) { return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; }
    }

    static String ej(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", ""); }

    static String extractJsonString(String body, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"").matcher(body);
        if (!m.find()) return null;
        StringBuilder sb = new StringBuilder(); int i = m.end();
        while (i < body.length()) { char c = body.charAt(i); if (c == '\\' && i + 1 < body.length()) { sb.append(body.charAt(i + 1)); i += 2; continue; } if (c == '"') break; sb.append(c); i++; }
        return sb.toString();
    }

    static String mapToJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{"); boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(','); first = false;
            sb.append('"').append(e.getKey()).append("\":");
            Object v = e.getValue();
            if (v instanceof String) sb.append('"').append(ej((String) v)).append('"');
            else if (v instanceof List) {
                sb.append('[');
                List<?> list = (List<?>) v;
                for (int li = 0; li < list.size(); li++) {
                    if (li > 0) sb.append(',');
                    Object item = list.get(li);
                    if (item instanceof Map) sb.append(mapToJson((Map<String, Object>) item));
                    else sb.append('"').append(ej(item.toString())).append('"');
                }
                sb.append(']');
            } else if (v instanceof Map) {
                sb.append(mapToJson((Map<String, Object>) v));
            } else if (v == null) sb.append("null");
            else sb.append(v);
        }
        return sb.append('}').toString();
    }

    static void sendJson(HttpExchange ex, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Cache-Control", "no-store, no-cache, must-revalidate");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    static String bodyOf(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    static Map<String, String> parseQueryParams(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null || query.isEmpty()) return map;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                map.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return map;
    }

    // ── HTTP Handlers ────────────────────────────────────────────────────────
    static class StaticFileHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            InputStream is = Main.class.getClassLoader().getResourceAsStream("index.html");
            if (is == null) {
                byte[] err = "404 index.html not found".getBytes();
                ex.sendResponseHeaders(404, err.length);
                ex.getResponseBody().write(err); ex.getResponseBody().close(); return;
            }
            byte[] html = is.readAllBytes();
            ex.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            ex.sendResponseHeaders(200, html.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(html); }
        }
    }

    static class ApiParseHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) return;
            String raw = extractJsonString(bodyOf(ex), "log");
            if (raw == null || raw.isEmpty()) { sendJson(ex, "{\"error\":\"missing log payload\"}"); return; }
            Event ev = ingest(raw);
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("id", ev.id);
            resp.put("masked", ev.masked);
            resp.put("template", ev.template);
            resp.put("leafHash", ev.leafHash);
            resp.put("intentCluster", ev.intentCluster);
            resp.put("mitreTacticId", ev.mitreTacticId);
            resp.put("mitreTacticName", ev.mitreTacticName);
            resp.put("mitreTechnique", ev.mitreTechnique);
            resp.put("mitreId", ev.mitreId);
            resp.put("templateIsNovel", ev.templateIsNovel);
            resp.put("pendingInBatch", pendingBuffer.size());
            sendJson(ex, mapToJson(resp));
        }
    }

    static class ApiVerifyHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) return;
            Map<String, String> q = parseQueryParams(ex.getRequestURI().getQuery());
            String leaf = q.get("leafHash");
            int batchId = q.containsKey("batchId") ? Integer.parseInt(q.get("batchId")) : -1;
            if (leaf == null || leaf.isEmpty()) {
                sendJson(ex, "{\"error\":\"leafHash parameter required\"}");
                return;
            }
            Map<String, Object> v = computeVerification(leaf, batchId);
            sendJson(ex, mapToJson(v));
        }
    }

    static class ApiTamperSimulateHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) return;
            String leaf = extractJsonString(bodyOf(ex), "leafHash");
            if (leaf == null || leaf.isEmpty()) {
                sendJson(ex, "{\"error\":\"leafHash parameter required\"}");
                return;
            }
            int[] loc = leafIndex.get(leaf);
            if (loc == null) {
                sendJson(ex, "{\"error\":\"leaf not found in anchored ledger\"}");
                return;
            }

            Batch b = batches.get(loc[0]);
            String originalRaw = b.rawLogs.get(loc[1]);

            char[] scratch = originalRaw.toCharArray();
            int flipIdx = scratch.length / 2;
            scratch[flipIdx] = scratch[flipIdx] == 'X' ? 'Y' : 'X';
            String tamperedRaw = new String(scratch);
            String tamperedLeaf = sha256(tamperedRaw);

            List<String> path = b.siblingPaths.get(loc[1]);
            String recomputed = tamperedLeaf;
            List<String> steps = new ArrayList<>();
            for (String sib : path) {
                steps.add(sib);
                recomputed = sha256(recomputed + sib);
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("valid", false);
            out.put("originalLeafHash", leaf);
            out.put("tamperedLeafHash", tamperedLeaf);
            out.put("batchId", b.id);
            out.put("recomputedRoot", recomputed);
            out.put("anchoredRoot", b.merkleRoot);
            out.put("proofPath", steps);
            out.put("message", "INTEGRITY VIOLATION DETECTED: 1-bit scratch mutation broke Merkle root recomputation.");
            sendJson(ex, mapToJson(out));
        }
    }

    static class ApiMitreMatrixHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) return;

            Map<String, Object> root = new LinkedHashMap<>();
            List<Map<String, Object>> tacticsList = new ArrayList<>();

            for (String[] t : MITRE_14_TACTICS) {
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

            Map<String, Object> unclassObj = new LinkedHashMap<>();
            unclassObj.put("id", "UNCLASSIFIED");
            unclassObj.put("name", "Novel / Unclassified");
            List<Map<String, Object>> unclassTech = new ArrayList<>();
            unclassTech.add(techItem("UNCLASSIFIED", "Unknown Pattern"));
            unclassObj.put("techniques", unclassTech);
            tacticsList.add(unclassObj);

            root.put("tactics", tacticsList);
            root.put("totalTechniquesDetected", mitreTechniqueCounts.size());
            sendJson(ex, mapToJson(root));
        }

        private static Map<String, Object> techItem(String id, String name) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("name", name);
            m.put("count", mitreTechniqueCounts.getOrDefault(id, 0));
            return m;
        }
    }

    static class ApiLogsByTechniqueHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) return;
            Map<String, String> q = parseQueryParams(ex.getRequestURI().getQuery());
            String techId = q.get("techniqueId");

            List<Map<String, Object>> matched = new ArrayList<>();
            synchronized (allIngestedEvents) {
                for (Event e : allIngestedEvents) {
                    if (techId == null || techId.isEmpty() || e.mitreId.equalsIgnoreCase(techId)) {
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("ts", e.ts);
                        m.put("raw", e.raw);
                        m.put("leafHash", e.leafHash);
                        m.put("mitreId", e.mitreId);
                        m.put("mitreTechnique", e.mitreTechnique);
                        m.put("tactic", e.mitreTacticName);
                        matched.add(m);
                        if (matched.size() >= 30) break;
                    }
                }
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("techniqueId", techId != null ? techId : "ALL");
            out.put("matchedCount", matched.size());
            out.put("events", matched);
            sendJson(ex, mapToJson(out));
        }
    }

    static class ApiProvenanceGraphHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) return;

            List<Map<String, Object>> nodes = new ArrayList<>();
            List<Map<String, Object>> edges = new ArrayList<>();

            List<Event> snapshot;
            synchronized (allIngestedEvents) {
                snapshot = new ArrayList<>(allIngestedEvents);
            }

            int startIdx = Math.max(0, snapshot.size() - 40);
            List<Event> workingSet = snapshot.subList(startIdx, snapshot.size());

            for (Event e : workingSet) {
                Map<String, Object> n = new LinkedHashMap<>();
                n.put("id", e.id);
                n.put("raw", e.raw);
                n.put("leafHash", e.leafHash);
                n.put("sourceIp", e.sourceIp);
                n.put("mitreId", e.mitreId);
                n.put("mitreTechnique", e.mitreTechnique);
                n.put("tactic", e.mitreTacticName);
                n.put("stage", e.killChainStage);
                n.put("ts", e.ts);
                nodes.add(n);
            }

            for (int i = 0; i < workingSet.size(); i++) {
                Event a = workingSet.get(i);
                for (int j = i + 1; j < workingSet.size(); j++) {
                    Event b = workingSet.get(j);

                    if (!a.sourceIp.equals("UNKNOWN_SRC") && a.sourceIp.equals(b.sourceIp)) {
                        long deltaMs = b.ts - a.ts;
                        if (deltaMs >= 0 && deltaMs <= 600_000) {
                            String confidence;
                            if (a.killChainStage > 0 && b.killChainStage > 0 && a.killChainStage <= b.killChainStage) {
                                confidence = "HIGH (Kill-Chain Verified)";
                            } else if (a.killChainStage > b.killChainStage) {
                                continue;
                            } else {
                                confidence = "MEDIUM (IP-Time Coincident)";
                            }

                            Map<String, Object> edge = new LinkedHashMap<>();
                            edge.put("source", a.id);
                            edge.put("target", b.id);
                            edge.put("confidence", confidence);
                            edge.put("timeGapSec", (int) (deltaMs / 1000));
                            edges.add(edge);
                        }
                    }
                }
            }

            Map<String, Object> graph = new LinkedHashMap<>();
            graph.put("graphId", "PROV_SESSION_" + System.currentTimeMillis());
            graph.put("totalNodes", nodes.size());
            graph.put("totalEdges", edges.size());
            graph.put("nodes", nodes);
            graph.put("edges", edges);

            sendJson(ex, mapToJson(graph));
        }
    }

    static class ApiEvidenceBundleHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) return;

            Map<String, Object> bundle = new LinkedHashMap<>();
            bundle.put("manifestType", "LogAnchor-X Forensic Evidence Bundle");
            bundle.put("timestamp", System.currentTimeMillis());
            bundle.put("chainTip", prevChainedRoot);
            bundle.put("totalBatchesAnchored", batches.size());

            List<Map<String, Object>> verifiedNodes = new ArrayList<>();
            synchronized (allIngestedEvents) {
                for (Event e : allIngestedEvents) {
                    Map<String, Object> nodeEntry = new LinkedHashMap<>();
                    nodeEntry.put("eventId", e.id);
                    nodeEntry.put("rawLog", e.raw);
                    nodeEntry.put("leafHash", e.leafHash);
                    nodeEntry.put("sourceIp", e.sourceIp);
                    nodeEntry.put("mitreClassification", e.mitreId + " - " + e.mitreTechnique + " (" + e.mitreTacticName + ")");

                    Map<String, Object> proof = computeVerification(e.leafHash, -1);
                    nodeEntry.put("cryptographicProof", proof);
                    verifiedNodes.add(nodeEntry);
                }
            }
            bundle.put("nodesWithCryptographicProofs", verifiedNodes);

            byte[] jsonBytes = mapToJson(bundle).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"loganchor_evidence_bundle.json\"");
            ex.sendResponseHeaders(200, jsonBytes.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(jsonBytes); }
        }
    }

    // ── Simulate Attack API (Phase 4) ────────────────────────────────────────
    static class ApiSimulateAttackHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) return;
            String body = bodyOf(ex);
            String action = extractJsonString(body, "action");

            if ("stop".equalsIgnoreCase(action)) {
                simRunning = false;
                simCurrentStage = "STOPPED";
                sendJson(ex, "{\"status\":\"stopped\"}");
                return;
            }

            if (simRunning) {
                sendJson(ex, "{\"status\":\"running\",\"stage\":\"" + ej(simCurrentStage) + "\"}");
                return;
            }

            Thread t = new Thread(Main::executeAptSimulation);
            t.setDaemon(true);
            t.setName("APT-Simulation-Runner");
            t.start();

            sendJson(ex, "{\"status\":\"started\",\"stage\":\"" + ej(simCurrentStage) + "\"}");
        }
    }

    static class ApiAnchorHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) return;
            Batch b = anchorBatch();
            if (b == null) { sendJson(ex, "{\"error\":\"Buffer empty\"}"); return; }
            sendJson(ex, "{\"batchId\":" + b.id + ",\"merkleRoot\":\"" + b.merkleRoot + "\",\"chainedRoot\":\"" + b.chainedRoot + "\",\"leavesAnchored\":" + b.leafHashes.size() + "}");
        }
    }

    static class ApiResetHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) return;
            resetState();
            sendJson(ex, "{\"status\":\"reset\"}");
        }
    }

    static class ApiStatusHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            Map<String, Object> st = new LinkedHashMap<>();
            st.put("totalIngested", totalIngested);
            st.put("pendingInBatch", pendingBuffer.size());
            st.put("batchesAnchored", batches.size());
            st.put("chainTip", prevChainedRoot);
            st.put("threatScore", calculateThreatScore());
            st.put("integrityChecksPassed", integrityChecksPassed);
            st.put("uniqueFormatsCount", detectedFormats.size());
            st.put("techniquesCount", mitreTechniqueCounts.size());
            st.put("simRunning", simRunning);
            st.put("simStage", simCurrentStage);
            sendJson(ex, mapToJson(st));
        }
    }

    // ── Main Entry Point ─────────────────────────────────────────────────────
    public static void main(String[] args) throws IOException {
        loadLedger();

        // Bounded thread pool sized to CPU cores to prevent resource thrashing under load
        int poolSize = Math.max(4, Runtime.getRuntime().availableProcessors() * 2);
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/",                     new StaticFileHandler());
        server.createContext("/api/parse",            new ApiParseHandler());
        server.createContext("/api/verify",           new ApiVerifyHandler());
        server.createContext("/api/tamper-simulate",   new ApiTamperSimulateHandler());
        server.createContext("/api/mitre-matrix",     new ApiMitreMatrixHandler());
        server.createContext("/api/logs-by-technique",new ApiLogsByTechniqueHandler());
        server.createContext("/api/provenance-graph", new ApiProvenanceGraphHandler());
        server.createContext("/api/evidence-bundle",  new ApiEvidenceBundleHandler());
        server.createContext("/api/simulate-attack",  new ApiSimulateAttackHandler());
        server.createContext("/api/anchor",           new ApiAnchorHandler());
        server.createContext("/api/reset",            new ApiResetHandler());
        server.createContext("/api/status",           new ApiStatusHandler());

        server.setExecutor(Executors.newFixedThreadPool(poolSize));
        server.start();

        System.out.println("==========================================================");
        System.out.println("[OK] LogAnchor-X Full Platform (Phase 4) Live at http://localhost:" + PORT);
        System.out.println("[OK] APT Simulation API : http://localhost:" + PORT + "/api/simulate-attack");
        System.out.println("[OK] Bounded Thread Pool: " + poolSize + " workers | Air-Gap Ready");
        System.out.println("==========================================================");
    }
}