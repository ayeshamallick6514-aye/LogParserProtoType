package org.example;

public class LogEvent {
    public String rawLog;
    public String maskedLog;
    public int wordCount;

    public LogEvent(String rawLog, String maskedLog) {
        this.rawLog = rawLog;
        this.maskedLog = maskedLog;
        this.wordCount = maskedLog.split(" ").length;
    }
}