package com.omnistrike.ui;

import com.omnistrike.framework.FindingsStore;
import com.omnistrike.framework.PrivacyManager;
import com.omnistrike.framework.ScopeManager;
import com.omnistrike.framework.SharedDataBus;
import com.omnistrike.model.Finding;
import com.omnistrike.model.Severity;

import static com.omnistrike.ui.CyberTheme.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.*;
import java.net.URI;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Visual graph view showing the relationship between hosts, subdomains,
 * and findings. Helps pentesters visualize the attack surface.
 *
 * Uses custom Java2D rendering — no external graph library needed.
 */
public class AttackSurfacePanel extends JPanel {

    private final FindingsStore findingsStore;
    private final ScopeManager scopeManager;
    private final SharedDataBus dataBus;

    // Graph data
    private final List<HostNode> nodes = new ArrayList<>();
    private final List<Edge> edges = new ArrayList<>();
    private HostNode selectedNode = null;

    // View transform
    private double zoom = 1.0;
    private double panX = 0, panY = 0;

    // UI components
    private final GraphCanvas canvas;
    private final JTextPane detailPane;
    private final JComboBox<String> severityFilter;
    private final JLabel statsLabel;

    // Layout constants
    private static final double NODE_W = 180;
    private static final double NODE_H = 64;
    private static final double X_SPACING = 40;
    private static final double Y_SPACING = 100;

    // ── Data model ──────────────────────────────────────────────────────────

    static class HostNode {
        String hostname;
        boolean isRoot;
        double x, y;
        double width = NODE_W, height = NODE_H;
        List<Finding> findings = new ArrayList<>();
        HostNode parent;
        List<HostNode> children = new ArrayList<>();
        Severity maxSeverity;
        Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
    }

    static class Edge {
        HostNode from, to;
        Edge(HostNode from, HostNode to) { this.from = from; this.to = to; }
    }

    // ── Constructor ─────────────────────────────────────────────────────────

    public AttackSurfacePanel(FindingsStore findingsStore, ScopeManager scopeManager,
                               SharedDataBus dataBus) {
        this.findingsStore = findingsStore;
        this.scopeManager = scopeManager;
        this.dataBus = dataBus;

        setLayout(new BorderLayout());
        setBackground(BG_DARK);

        // Create canvas early so toolbar lambdas can reference it
        canvas = new GraphCanvas();

        // ── Toolbar ──
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        toolbar.setBackground(BG_DARK);

        JButton refreshBtn = new JButton("Refresh");
        styleButton(refreshBtn, NEON_CYAN);
        refreshBtn.addActionListener(e -> refreshGraph());
        toolbar.add(refreshBtn);

        JButton fitBtn = new JButton("Fit to View");
        styleButton(fitBtn, null);
        fitBtn.addActionListener(e -> fitToView());
        toolbar.add(fitBtn);

        JButton resetBtn = new JButton("Reset Zoom");
        styleButton(resetBtn, null);
        resetBtn.addActionListener(e -> { zoom = 1.0; panX = 0; panY = 0; canvas.repaint(); });
        toolbar.add(resetBtn);

        toolbar.add(Box.createHorizontalStrut(16));
        JLabel filterLabel = new JLabel("Min Severity:");
        filterLabel.setForeground(FG_SECONDARY);
        filterLabel.setFont(MONO_LABEL);
        toolbar.add(filterLabel);

        severityFilter = new JComboBox<>(new String[]{
                "All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"});
        styleComboBox(severityFilter);
        toolbar.add(severityFilter);

        toolbar.add(Box.createHorizontalStrut(16));
        statsLabel = new JLabel("Hosts: 0 | Findings: 0");
        statsLabel.setForeground(FG_SECONDARY);
        statsLabel.setFont(MONO_SMALL);
        toolbar.add(statsLabel);

        add(toolbar, BorderLayout.NORTH);

        severityFilter.addActionListener(e -> canvas.repaint());

        // ── Detail panel ──
        detailPane = new JTextPane();
        detailPane.setContentType("text/html");
        detailPane.setEditable(false);
        detailPane.setBackground(BG_PANEL);
        detailPane.setForeground(FG_PRIMARY);
        detailPane.setFont(MONO_SMALL);
        detailPane.setText(htmlWrap("<i style='color:gray'>Click a host node to see details</i>"));
        JScrollPane detailScroll = new JScrollPane(detailPane);
        styleScrollPane(detailScroll);
        detailScroll.setPreferredSize(new Dimension(280, 0));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, canvas, detailScroll);
        split.setDividerLocation(600);
        split.setResizeWeight(0.75);
        styleSplitPane(split);
        add(split, BorderLayout.CENTER);

        // Build initial graph
        refreshGraph();
    }

    // ── Graph building ──────────────────────────────────────────────────────

    public void refreshGraph() {
        nodes.clear();
        edges.clear();
        selectedNode = null;

        // Collect all hosts from findings
        Map<String, List<Finding>> hostFindings = new LinkedHashMap<>();
        for (Finding f : findingsStore.getAllFindings()) {
            String host = extractHost(f.getUrl());
            if (host != null && !host.isEmpty()) {
                hostFindings.computeIfAbsent(host, k -> new ArrayList<>()).add(f);
            }
        }

        // Also add discovered subdomains (even if no findings yet)
        if (dataBus != null) {
            for (String sub : dataBus.getSet("discovered-subdomains")) {
                hostFindings.putIfAbsent(sub.toLowerCase(), new ArrayList<>());
            }
        }

        if (hostFindings.isEmpty()) {
            statsLabel.setText("Hosts: 0 | Findings: 0 — Start a scan to populate");
            detailPane.setText(htmlWrap(
                    "<h3 style='color:#00F0FF'>No data yet</h3>"
                            + "<p style='color:gray'>Configure target scope, start scanning, then click Refresh.</p>"));
            canvas.repaint();
            return;
        }

        // Determine root domains from scope
        Set<String> scopeDomains = scopeManager.getTargetDomains();

        // Create nodes
        Map<String, HostNode> nodeMap = new LinkedHashMap<>();
        for (var entry : hostFindings.entrySet()) {
            HostNode node = new HostNode();
            node.hostname = entry.getKey();
            node.findings = entry.getValue();
            node.isRoot = scopeDomains.contains(entry.getKey());

            // Compute severity stats
            for (Finding f : node.findings) {
                node.severityCounts.merge(f.getSeverity(), 1, Integer::sum);
                if (node.maxSeverity == null || f.getSeverity().ordinal() < node.maxSeverity.ordinal()) {
                    node.maxSeverity = f.getSeverity();
                }
            }

            nodeMap.put(entry.getKey(), node);
            nodes.add(node);
        }

        // Build parent-child relationships
        for (HostNode node : nodes) {
            if (node.isRoot) continue;
            HostNode parent = findParent(node.hostname, nodeMap, scopeDomains);
            if (parent != null) {
                node.parent = parent;
                parent.children.add(node);
                edges.add(new Edge(parent, node));
            }
        }

        // Nodes without a parent or root status: try to make them roots
        // or attach to the closest scope domain
        for (HostNode node : nodes) {
            if (!node.isRoot && node.parent == null) {
                // Check if it's a subdomain of any scope domain
                for (String scope : scopeDomains) {
                    if (node.hostname.endsWith("." + scope)) {
                        // Create root node for scope domain if it doesn't exist
                        HostNode root = nodeMap.get(scope);
                        if (root == null) {
                            root = new HostNode();
                            root.hostname = scope;
                            root.isRoot = true;
                            root.findings = new ArrayList<>();
                            nodeMap.put(scope, root);
                            nodes.add(root);
                        }
                        node.parent = root;
                        root.children.add(node);
                        edges.add(new Edge(root, node));
                        break;
                    }
                }
                // Still no parent — treat as root
                if (node.parent == null) {
                    node.isRoot = true;
                }
            }
        }

        // Layout
        layoutTree();

        // Update stats
        int totalFindings = hostFindings.values().stream().mapToInt(List::size).sum();
        statsLabel.setText("Hosts: " + nodes.size() + " | Findings: " + totalFindings);

        canvas.repaint();
    }

    private HostNode findParent(String host, Map<String, HostNode> nodeMap, Set<String> scopeDomains) {
        // Walk up domain hierarchy to find the closest parent node
        int dotIdx = host.indexOf('.');
        while (dotIdx > 0) {
            String parent = host.substring(dotIdx + 1);
            if (nodeMap.containsKey(parent)) {
                return nodeMap.get(parent);
            }
            dotIdx = host.indexOf('.', dotIdx + 1);
        }
        return null;
    }

    // ── Tree layout ─────────────────────────────────────────────────────────

    private void layoutTree() {
        List<HostNode> roots = nodes.stream()
                .filter(n -> n.parent == null || n.isRoot)
                .collect(Collectors.toList());

        if (roots.isEmpty()) return;

        double currentX = 0;
        for (HostNode root : roots) {
            double subtreeW = computeSubtreeWidth(root);
            positionNode(root, currentX + subtreeW / 2, 40);
            currentX += subtreeW + X_SPACING * 2;
        }

        // Center everything
        if (!nodes.isEmpty()) {
            double minX = nodes.stream().mapToDouble(n -> n.x).min().orElse(0);
            double maxX = nodes.stream().mapToDouble(n -> n.x + n.width).max().orElse(0);
            double maxY = nodes.stream().mapToDouble(n -> n.y + n.height).max().orElse(0);
            double centerX = (maxX + minX) / 2;
            double centerY = maxY / 2;
            panX = -centerX + 400;
            panY = -centerY + 200;
        }
    }

    private double computeSubtreeWidth(HostNode node) {
        if (node.children.isEmpty()) {
            return node.width;
        }
        double childrenWidth = 0;
        for (HostNode child : node.children) {
            childrenWidth += computeSubtreeWidth(child);
        }
        childrenWidth += (node.children.size() - 1) * X_SPACING;
        return Math.max(node.width, childrenWidth);
    }

    private void positionNode(HostNode node, double centerX, double y) {
        node.x = centerX - node.width / 2;
        node.y = y;

        if (!node.children.isEmpty()) {
            double totalW = 0;
            List<Double> childWidths = new ArrayList<>();
            for (HostNode child : node.children) {
                double w = computeSubtreeWidth(child);
                childWidths.add(w);
                totalW += w;
            }
            totalW += (node.children.size() - 1) * X_SPACING;

            double cx = centerX - totalW / 2;
            for (int i = 0; i < node.children.size(); i++) {
                double cw = childWidths.get(i);
                positionNode(node.children.get(i), cx + cw / 2, y + Y_SPACING);
                cx += cw + X_SPACING;
            }
        }
    }

    // ── View controls ───────────────────────────────────────────────────────

    private void fitToView() {
        if (nodes.isEmpty()) return;

        double minX = nodes.stream().mapToDouble(n -> n.x).min().orElse(0);
        double maxX = nodes.stream().mapToDouble(n -> n.x + n.width).max().orElse(0);
        double minY = nodes.stream().mapToDouble(n -> n.y).min().orElse(0);
        double maxY = nodes.stream().mapToDouble(n -> n.y + n.height).max().orElse(0);

        double graphW = maxX - minX + 80;
        double graphH = maxY - minY + 80;
        double canvasW = canvas.getWidth();
        double canvasH = canvas.getHeight();

        if (graphW <= 0 || graphH <= 0 || canvasW <= 0 || canvasH <= 0) return;

        zoom = Math.min(canvasW / graphW, canvasH / graphH);
        zoom = Math.max(0.2, Math.min(zoom, 3.0));
        panX = -minX + (canvasW / zoom - graphW) / 2 + 40;
        panY = -minY + (canvasH / zoom - graphH) / 2 + 40;

        canvas.repaint();
    }

    // ── Node lookup ─────────────────────────────────────────────────────────

    private HostNode nodeAt(double mx, double my) {
        // Transform mouse coords to graph coords
        double gx = mx / zoom - panX;
        double gy = my / zoom - panY;

        // Search in reverse order (topmost first)
        for (int i = nodes.size() - 1; i >= 0; i--) {
            HostNode n = nodes.get(i);
            if (!isNodeVisible(n)) continue;
            if (gx >= n.x && gx <= n.x + n.width && gy >= n.y && gy <= n.y + n.height) {
                return n;
            }
        }
        return null;
    }

    private boolean isNodeVisible(HostNode node) {  // renamed to avoid Component.isVisible() clash
        String filter = (String) severityFilter.getSelectedItem();
        if (filter == null || "All".equals(filter)) return true;
        if (node.maxSeverity == null) return "All".equals(filter);
        Severity minSev = Severity.valueOf(filter);
        return node.maxSeverity.ordinal() <= minSev.ordinal();
    }

    // ── Detail display ──────────────────────────────────────────────────────

    private void showNodeDetails(HostNode node) {
        if (node == null) {
            detailPane.setText(htmlWrap("<i style='color:gray'>Click a host node to see details</i>"));
            return;
        }

        StringBuilder html = new StringBuilder();
        html.append("<h2 style='color:#00F0FF; margin:0'>").append(esc(displayHost(node.hostname))).append("</h2>");
        html.append("<p style='color:gray'>").append(node.isRoot ? "Root domain" : "Subdomain");
        if (node.parent != null) {
            html.append(" of ").append(esc(displayHost(node.parent.hostname)));
        }
        html.append("</p>");

        if (node.findings.isEmpty()) {
            html.append("<p style='color:gray'><i>No findings for this host</i></p>");
        } else {
            // Severity summary
            html.append("<table cellpadding='2'>");
            for (Severity s : Severity.values()) {
                int count = node.severityCounts.getOrDefault(s, 0);
                if (count > 0) {
                    html.append("<tr><td style='color:").append(severityHex(s)).append("; font-weight:bold'>")
                            .append(s).append("</td><td>").append(count).append("</td></tr>");
                }
            }
            html.append("</table><hr>");

            // Finding list
            html.append("<h3 style='color:#E0E0FF'>Findings (").append(node.findings.size()).append(")</h3>");
            for (Finding f : node.findings) {
                html.append("<p style='margin:4px 0'>");
                html.append("<span style='color:").append(severityHex(f.getSeverity()))
                        .append("; font-weight:bold'>[").append(f.getSeverity()).append("]</span> ");
                html.append("<span style='color:#E0E0FF'>")
                        .append(esc(PrivacyManager.maskForDisplay(f.getTitle()))).append("</span>");
                if (f.getParameter() != null && !f.getParameter().isEmpty()) {
                    html.append(" <span style='color:gray'>(")
                            .append(esc(PrivacyManager.maskForDisplay(f.getParameter()))).append(")</span>");
                }
                html.append("<br><span style='color:gray; font-size:0.9em'>")
                        .append(esc(f.getModuleId())).append("</span>");
                html.append("</p>");
            }

            // Children summary
            if (!node.children.isEmpty()) {
                html.append("<hr><h3 style='color:#E0E0FF'>Subdomains (")
                        .append(node.children.size()).append(")</h3>");
                for (HostNode child : node.children) {
                    html.append("<p style='color:#4488FF'>").append(esc(displayHost(child.hostname)))
                            .append(" <span style='color:gray'>(")
                            .append(child.findings.size()).append(" findings)</span></p>");
                }
            }
        }

        detailPane.setText(htmlWrap(html.toString()));
        detailPane.setCaretPosition(0);
    }

    private String displayHost(String hostname) {
        return PrivacyManager.maskValueForDisplay("HOST", hostname);
    }

    /** Repaints host labels and the selected detail card after privacy mode changes. */
    public void refreshPrivacyDisplay() {
        showNodeDetails(selectedNode);
        canvas.repaint();
    }

    // ── Graph canvas (custom rendering) ─────────────────────────────────────

    class GraphCanvas extends JPanel {

        private Point dragStart;
        private double dragPanX, dragPanY;

        GraphCanvas() {
            setBackground(BG_DARK);
            setFocusable(true);

            addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    requestFocusInWindow();
                    if (SwingUtilities.isLeftMouseButton(e)) {
                        HostNode hit = nodeAt(e.getX(), e.getY());
                        if (hit != null) {
                            selectedNode = hit;
                            showNodeDetails(hit);
                        } else {
                            // Start panning
                            dragStart = e.getPoint();
                            dragPanX = panX;
                            dragPanY = panY;
                        }
                        repaint();
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    dragStart = null;
                }
            });

            addMouseMotionListener(new MouseMotionAdapter() {
                @Override
                public void mouseDragged(MouseEvent e) {
                    if (dragStart != null && SwingUtilities.isLeftMouseButton(e)) {
                        double dx = (e.getX() - dragStart.x) / zoom;
                        double dy = (e.getY() - dragStart.y) / zoom;
                        panX = dragPanX + dx;
                        panY = dragPanY + dy;
                        repaint();
                    }
                }
            });

            addMouseWheelListener(e -> {
                double mx = e.getX();
                double my = e.getY();
                // Graph position under mouse before zoom
                double gxBefore = mx / zoom - panX;
                double gyBefore = my / zoom - panY;

                double factor = e.getWheelRotation() < 0 ? 1.15 : 1 / 1.15;
                zoom = Math.max(0.15, Math.min(zoom * factor, 5.0));

                // Adjust pan so the same graph point stays under the mouse
                panX = mx / zoom - gxBefore;
                panY = my / zoom - gyBefore;
                repaint();
            });
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            if (nodes.isEmpty()) {
                g2.setColor(FG_DIM);
                g2.setFont(MONO_FONT);
                g2.drawString("No data — click Refresh after scanning", 50, getHeight() / 2);
                g2.dispose();
                return;
            }

            // Draw grid dots (subtle background pattern)
            paintGrid(g2);

            // Draw edges
            for (Edge edge : edges) {
                if (isNodeVisible(edge.from) || isNodeVisible(edge.to)) {
                    paintEdge(g2, edge);
                }
            }

            // Draw nodes
            for (HostNode node : nodes) {
                if (isNodeVisible(node)) {
                    paintNode(g2, node);
                }
            }

            // Draw legend
            paintLegend(g2);

            g2.dispose();
        }

        private void paintGrid(Graphics2D g2) {
            g2.setColor(new Color(BORDER.getRed(), BORDER.getGreen(), BORDER.getBlue(), 30));
            double step = 60 * zoom;
            if (step < 10) return; // Too dense
            double ox = (panX * zoom) % step;
            double oy = (panY * zoom) % step;
            for (double x = ox; x < getWidth(); x += step) {
                for (double y = oy; y < getHeight(); y += step) {
                    g2.fillOval((int) x - 1, (int) y - 1, 2, 2);
                }
            }
        }

        private void paintEdge(Graphics2D g2, Edge edge) {
            double x1 = (edge.from.x + edge.from.width / 2 + panX) * zoom;
            double y1 = (edge.from.y + edge.from.height + panY) * zoom;
            double x2 = (edge.to.x + edge.to.width / 2 + panX) * zoom;
            double y2 = (edge.to.y + panY) * zoom;

            double midY = (y1 + y2) / 2;

            g2.setColor(new Color(BORDER.getRed(), BORDER.getGreen(), BORDER.getBlue(), 120));
            g2.setStroke(new BasicStroke((float) (1.5 * zoom), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));

            CubicCurve2D curve = new CubicCurve2D.Double(x1, y1, x1, midY, x2, midY, x2, y2);
            g2.draw(curve);

            // Small arrowhead at target
            double arrowSize = 6 * zoom;
            Path2D arrow = new Path2D.Double();
            arrow.moveTo(x2, y2);
            arrow.lineTo(x2 - arrowSize / 2, y2 - arrowSize);
            arrow.lineTo(x2 + arrowSize / 2, y2 - arrowSize);
            arrow.closePath();
            g2.fill(arrow);
        }

        private void paintNode(Graphics2D g2, HostNode node) {
            double sx = (node.x + panX) * zoom;
            double sy = (node.y + panY) * zoom;
            double sw = node.width * zoom;
            double sh = node.height * zoom;

            if (sx + sw < 0 || sy + sh < 0 || sx > getWidth() || sy > getHeight()) {
                return; // Offscreen — skip
            }

            RoundRectangle2D rect = new RoundRectangle2D.Double(sx, sy, sw, sh, 10 * zoom, 10 * zoom);

            // Background
            Color bg = (node == selectedNode) ? BG_HOVER : BG_PANEL;
            g2.setColor(bg);
            g2.fill(rect);

            // Glow effect for selected node
            if (node == selectedNode) {
                Color glowColor = severityColor(node.maxSeverity);
                for (int i = 3; i >= 1; i--) {
                    float alpha = 0.06f * (4 - i);
                    g2.setColor(new Color(glowColor.getRed(), glowColor.getGreen(),
                            glowColor.getBlue(), (int) (alpha * 255)));
                    g2.setStroke(new BasicStroke((float) ((2 + i * 2) * zoom)));
                    g2.draw(rect);
                }
            }

            // Border
            Color borderColor = severityColor(node.maxSeverity);
            g2.setColor(borderColor);
            g2.setStroke(new BasicStroke((float) ((node == selectedNode ? 2.5 : 1.5) * zoom)));
            g2.draw(rect);

            // Root indicator (small diamond)
            if (node.isRoot) {
                double dSize = 5 * zoom;
                double dx = sx + sw - 12 * zoom;
                double dy = sy + 8 * zoom;
                Path2D diamond = new Path2D.Double();
                diamond.moveTo(dx, dy - dSize);
                diamond.lineTo(dx + dSize, dy);
                diamond.lineTo(dx, dy + dSize);
                diamond.lineTo(dx - dSize, dy);
                diamond.closePath();
                g2.setColor(NEON_CYAN);
                g2.fill(diamond);
            }

            // Hostname label
            float fontSize = (float) Math.max(8, 12 * zoom);
            g2.setFont(MONO_FONT.deriveFont(fontSize));
            FontMetrics fm = g2.getFontMetrics();
            String label = truncateLabel(displayHost(node.hostname), (int) (sw - 12 * zoom), fm);
            g2.setColor(FG_PRIMARY);
            double textX = sx + (sw - fm.stringWidth(label)) / 2;
            double textY = sy + sh / 2 - 4 * zoom;
            g2.drawString(label, (float) textX, (float) textY);

            // Finding count
            if (!node.findings.isEmpty()) {
                float smallSize = (float) Math.max(7, 10 * zoom);
                g2.setFont(MONO_SMALL.deriveFont(smallSize));
                fm = g2.getFontMetrics();
                String countStr = node.findings.size() + " finding" + (node.findings.size() != 1 ? "s" : "");
                g2.setColor(FG_SECONDARY);
                double countX = sx + (sw - fm.stringWidth(countStr)) / 2;
                g2.drawString(countStr, (float) countX, (float) (textY + 14 * zoom));
            }

            // Severity dots at bottom
            paintSeverityDots(g2, node, sx, sy, sw, sh);
        }

        private void paintSeverityDots(Graphics2D g2, HostNode node, double sx, double sy,
                                         double sw, double sh) {
            double dotSize = 6 * zoom;
            double dotSpacing = 3 * zoom;
            List<Severity> severities = new ArrayList<>();
            for (Severity s : Severity.values()) {
                if (node.severityCounts.getOrDefault(s, 0) > 0) {
                    severities.add(s);
                }
            }
            if (severities.isEmpty()) return;

            double totalW = severities.size() * dotSize + (severities.size() - 1) * dotSpacing;
            double dotX = sx + (sw - totalW) / 2;
            double dotY = sy + sh - dotSize - 4 * zoom;

            for (Severity s : severities) {
                g2.setColor(severityColor(s));
                g2.fill(new Ellipse2D.Double(dotX, dotY, dotSize, dotSize));
                dotX += dotSize + dotSpacing;
            }
        }

        private void paintLegend(Graphics2D g2) {
            int lx = getWidth() - 160;
            int ly = getHeight() - 130;
            int lw = 150;
            int lh = 120;

            // Background
            g2.setColor(new Color(BG_PANEL.getRed(), BG_PANEL.getGreen(), BG_PANEL.getBlue(), 220));
            g2.fillRoundRect(lx, ly, lw, lh, 8, 8);
            g2.setColor(BORDER);
            g2.drawRoundRect(lx, ly, lw, lh, 8, 8);

            g2.setFont(MONO_SMALL.deriveFont(10f));
            g2.setColor(FG_SECONDARY);
            g2.drawString("Severity", lx + 10, ly + 14);

            Severity[] sevs = Severity.values();
            for (int i = 0; i < sevs.length; i++) {
                int row = ly + 26 + i * 18;
                g2.setColor(severityColor(sevs[i]));
                g2.fillOval(lx + 12, row, 8, 8);
                g2.setColor(FG_PRIMARY);
                g2.setFont(MONO_SMALL.deriveFont(10f));
                g2.drawString(sevs[i].name(), lx + 26, row + 8);
            }
        }

        private String truncateLabel(String text, int maxWidth, FontMetrics fm) {
            if (fm.stringWidth(text) <= maxWidth) return text;
            String ellipsis = "...";
            int ellipsisW = fm.stringWidth(ellipsis);
            for (int i = text.length() - 1; i > 0; i--) {
                if (fm.stringWidth(text.substring(0, i)) + ellipsisW <= maxWidth) {
                    return text.substring(0, i) + ellipsis;
                }
            }
            return ellipsis;
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private Color severityColor(Severity sev) {
        if (sev == null) return BORDER;
        return switch (sev) {
            case CRITICAL -> SEV_CRITICAL;
            case HIGH -> SEV_HIGH;
            case MEDIUM -> SEV_MEDIUM;
            case LOW -> SEV_LOW;
            case INFO -> SEV_INFO;
        };
    }

    private String severityHex(Severity sev) {
        Color c = severityColor(sev);
        return String.format("#%02X%02X%02X", c.getRed(), c.getGreen(), c.getBlue());
    }

    private String extractHost(String url) {
        if (url == null || url.isEmpty()) return null;
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            return host != null ? host.toLowerCase() : null;
        } catch (Exception e) {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return null;
            String rest = url.substring(schemeEnd + 3);
            int slash = rest.indexOf('/');
            int colon = rest.indexOf(':');
            int end = rest.length();
            if (slash > 0) end = Math.min(end, slash);
            if (colon > 0) end = Math.min(end, colon);
            return end > 0 ? rest.substring(0, end).toLowerCase() : null;
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String htmlWrap(String body) {
        return "<html><body style='font-family:monospace; background:#14142800; color:#E0E0FF; padding:8px'>"
                + body + "</body></html>";
    }
}
