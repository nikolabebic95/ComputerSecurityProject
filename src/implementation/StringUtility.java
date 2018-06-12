package implementation;

public final class StringUtility {
    private StringUtility() {}

    public static String getProperSubjectIssuerString(String issuer) {
        return issuer.replaceAll("\\s*,\\s*", ",");
    }

}
