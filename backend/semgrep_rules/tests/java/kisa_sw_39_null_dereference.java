import java.util.Map;
class kisa_sw_39_null_dereference {
    int unsafe(Map<String,String> map) {
        // ruleid: kisa.sw39.java.nullable-map-result-dereference
        return map.get("name").length();
    }
    int safe(Map<String,String> map) {
        String value = map.get("name");
        // ok: kisa.sw39.java.nullable-map-result-dereference
        return value == null ? 0 : value.length();
    }
}
