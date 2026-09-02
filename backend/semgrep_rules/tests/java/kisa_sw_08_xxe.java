import javax.xml.parsers.DocumentBuilderFactory;

class kisa_sw_08_xxe {
    void unsafe() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        // ruleid: kisa.sw08.java.unsafe-xml-external-entity
        f.setExpandEntityReferences(true);
    }
    void safe() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        // ok: kisa.sw08.java.unsafe-xml-external-entity
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    }
}
