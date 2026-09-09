package org.example;

import java.util.HashMap;
import java.util.Map;

public class ParseNode {
    public Map<String, ParseNode> children = new HashMap<>();
    public String logTemplate = "";
}