package com.acme.shop;

import java.io.IOException;
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/** Reads invoices sent by suppliers. */
public final class InvoiceParser {
    private InvoiceParser() {
    }

    public static Document parse(InputStream in) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return factory.newDocumentBuilder().parse(in);
    }

    public static Document parseSafely(InputStream in) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder().parse(in);
    }

    public static String supplierName(Document invoice, String supplierId) throws XPathExpressionException {
        return XPathFactory.newInstance().newXPath().evaluate("//supplier[@id='" + supplierId + "']/name", invoice);
    }
}
