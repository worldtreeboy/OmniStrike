package com.omnistrike.modules.injection.deser;

/**
 * Represents a location where serialized data was detected in an HTTP request.
 */
public class SerializedDataLocation {

    public enum LocationType {
        COOKIE, HEADER, BODY_PARAM, JSON_FIELD, QUERY_PARAM, RAW_BODY
    }

    private final LocationType locationType;
    private final String paramName;
    private final String rawValue;
    private final DeserPayloadGenerator.Language language;
    private final int startOffset;
    private final int endOffset;

    public SerializedDataLocation(LocationType locationType, String paramName,
                                  String rawValue, DeserPayloadGenerator.Language language,
                                  int startOffset, int endOffset) {
        this.locationType = locationType;
        this.paramName = paramName;
        this.rawValue = rawValue;
        this.language = language;
        this.startOffset = startOffset;
        this.endOffset = endOffset;
    }

    public LocationType getLocationType() { return locationType; }
    public String getParamName() { return paramName; }
    public String getRawValue() { return rawValue; }
    public DeserPayloadGenerator.Language getLanguage() { return language; }
    public int getStartOffset() { return startOffset; }
    public int getEndOffset() { return endOffset; }

    @Override
    public String toString() {
        return language + " serialized data in " + locationType
                + (paramName != null ? " [" + paramName + "]" : "")
                + " (offset " + startOffset + "-" + endOffset + ")";
    }
}
