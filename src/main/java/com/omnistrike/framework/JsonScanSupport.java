package com.omnistrike.framework;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/** Structural JSON target discovery and mutation for active scanners. */
public final class JsonScanSupport {
    private static final int MAX_NESTING = 128;

    private JsonScanSupport() {}

    public record Target(String displayName, String value, List<Object> path) {
        public Target {
            path = List.copyOf(path);
        }

        public String identityName() {
            StringBuilder out = new StringBuilder();
            for (Object part : path) {
                if (part instanceof String key) {
                    out.append('/').append(key.replace("~", "~0").replace("/", "~1"));
                } else {
                    out.append('/').append(part);
                }
            }
            return out.toString();
        }

        public boolean matchesParameterName(String requested) {
            if (requested == null) return false;
            if (displayName.equalsIgnoreCase(requested)) return true;
            if (!path.isEmpty() && path.get(path.size() - 1) instanceof String key) {
                return key.equalsIgnoreCase(requested);
            }
            return false;
        }
    }

    private record Pending(JsonElement element, String displayName, List<Object> path) {}

    public static List<Target> extractTargets(String json) {
        List<Target> targets = new ArrayList<>();
        requireSafeNesting(json);
        JsonElement root = JsonParser.parseString(json);
        Deque<Pending> pending = new ArrayDeque<>();
        pending.push(new Pending(root, "", List.of()));

        while (!pending.isEmpty()) {
            Pending item = pending.pop();
            JsonElement element = item.element();
            if (element == null) continue;

            if (element.isJsonNull()) {
                if (!item.path().isEmpty()) {
                    targets.add(new Target(item.displayName(), "null", item.path()));
                }
                continue;
            }

            if (element.isJsonPrimitive()) {
                JsonPrimitive primitive = element.getAsJsonPrimitive();
                if (!item.path().isEmpty()
                        && (primitive.isString() || primitive.isNumber() || primitive.isBoolean())) {
                    targets.add(new Target(item.displayName(), primitive.getAsString(), item.path()));
                }
                continue;
            }

            if (element.isJsonObject()) {
                JsonObject object = element.getAsJsonObject();
                List<String> keys = new ArrayList<>(object.keySet());
                for (int i = keys.size() - 1; i >= 0; i--) {
                    String key = keys.get(i);
                    List<Object> path = new ArrayList<>(item.path());
                    path.add(key);
                    pending.push(new Pending(object.get(key), appendKey(item.displayName(), key), path));
                }
            } else if (element.isJsonArray()) {
                JsonArray array = element.getAsJsonArray();
                for (int i = array.size() - 1; i >= 0; i--) {
                    List<Object> path = new ArrayList<>(item.path());
                    path.add(i);
                    pending.push(new Pending(array.get(i), item.displayName() + "[" + i + "]", path));
                }
            }
        }
        return targets;
    }

    public static String replaceValue(String json, List<Object> path, String value) {
        try {
            if (path == null || path.isEmpty()) return json;
            requireSafeNesting(json);
            JsonElement root = JsonParser.parseString(json);
            JsonElement current = root;
            for (int i = 0; i < path.size() - 1; i++) {
                Object part = path.get(i);
                if (part instanceof String key && current.isJsonObject()) {
                    current = current.getAsJsonObject().get(key);
                } else if (part instanceof Integer index && current.isJsonArray()
                        && index >= 0 && index < current.getAsJsonArray().size()) {
                    current = current.getAsJsonArray().get(index);
                } else {
                    return json;
                }
                if (current == null) return json;
            }

            Object leaf = path.get(path.size() - 1);
            JsonPrimitive replacement = new JsonPrimitive(value);
            if (leaf instanceof String key && current.isJsonObject() && current.getAsJsonObject().has(key)) {
                current.getAsJsonObject().add(key, replacement);
            } else if (leaf instanceof Integer index && current.isJsonArray()
                    && index >= 0 && index < current.getAsJsonArray().size()) {
                current.getAsJsonArray().set(index, replacement);
            } else {
                return json;
            }
            return new Gson().toJson(root);
        } catch (Exception ignored) {
            return json;
        }
    }

    private static String appendKey(String prefix, String key) {
        if (key.matches("[A-Za-z_][A-Za-z0-9_-]*")) {
            return prefix.isEmpty() ? key : prefix + "." + key;
        }
        String quoted = key.replace("\\", "\\\\").replace("\"", "\\\"");
        return prefix + "[\"" + quoted + "\"]";
    }

    /** Reject pathological nesting before Gson's recursive parser can overflow the worker stack. */
    private static void requireSafeNesting(String json) {
        if (json == null) throw new IllegalArgumentException("JSON must not be null");
        int depth = 0;
        boolean quoted = false;
        boolean escaped = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (quoted) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') quoted = false;
                continue;
            }
            if (c == '"') quoted = true;
            else if (c == '{' || c == '[') {
                if (++depth > MAX_NESTING) {
                    throw new IllegalArgumentException("JSON nesting exceeds " + MAX_NESTING);
                }
            } else if (c == '}' || c == ']') {
                depth--;
            }
        }
    }
}
