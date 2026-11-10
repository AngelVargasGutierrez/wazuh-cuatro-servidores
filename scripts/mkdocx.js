const fs = require("fs"), path = require("path");
const D = require("docx");
const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, WidthType, ImageRun, Footer, PageNumber, AlignmentType, BorderStyle, ShadingType, LevelFormat, HeadingLevel, TabStopType, VerticalAlign, ExternalHyperlink } = D;
const dir = "D:/ARTICULO_WAZUH/documento", fig = "D:/ARTICULO_WAZUH/figuras";
const J = JSON.parse(fs.readFileSync(path.join(dir, "documento.json"), "utf8"));
const SERIF = "Cambria", SANS = "Segoe UI", NAVY = "1F3A7A";
const W = 9638; // A4 con margenes de 18 mm
const run = (r, o = {}) => new TextRun({ text: r.t, bold: r.b || o.bold, italics: r.i || o.italics, font: r.c ? "Consolas" : (o.font || SERIF), size: r.c ? (o.size ? o.size - 2 : 18) : (o.size || 21), color: o.color });
const p = (rs, o = {}) => new Paragraph({ children: rs.map(r => run(r, o)), alignment: o.align || AlignmentType.JUSTIFIED, spacing: { after: o.after ?? 130, before: o.before ?? 0, line: o.line ?? 310 }, keepNext: o.keepNext, keepLines: o.keepLines });
const border = { style: BorderStyle.SINGLE, size: 4, color: "CFD6E4" };
const borders = { top: border, bottom: border, left: border, right: border };

function len(c) { return c.map(r => r.t).join("").length; }
function widths(rows) {
  const n = rows[0].length, m = Array(n).fill(0);
  rows.forEach(r => r.forEach((c, i) => { m[i] = Math.max(m[i], Math.min(len(c), 46)); }));
  const w = m.map(x => Math.max(x, 6)); const s = w.reduce((a, b) => a + b, 0);
  const res = w.map(x => Math.round(W * x / s)); res[n - 1] += W - res.reduce((a, b) => a + b, 0); return res;
}
function table(b) {
  const cw = widths(b.rows);
  return new Table({
    width: { size: W, type: WidthType.DXA }, columnWidths: cw,
    rows: b.rows.map((r, ri) => new TableRow({
      tableHeader: ri === 0, cantSplit: true,
      children: r.map((c, i) => new TableCell({
        width: { size: cw[i], type: WidthType.DXA }, borders, verticalAlign: VerticalAlign.TOP,
        margins: { top: 40, bottom: 40, left: 70, right: 70 },
        shading: ri === 0 ? { type: ShadingType.CLEAR, fill: "EEF2F9", color: "auto" } : undefined,
        children: [new Paragraph({ spacing: { after: 0, line: 240 }, children: (c.length ? c : [{ t: "" }]).map(x => run(x, { font: SANS, size: 17, bold: ri === 0 })) })],
      })),
    })),
  });
}
const nota = t => new Paragraph({ spacing: { before: 60, after: 200, line: 250 }, children: [new TextRun({ text: "Nota. ", italics: true, font: SERIF, size: 18 }), new TextRun({ text: t, font: SERIF, size: 18 })] });
const cap = (label, title) => [
  new Paragraph({ keepNext: true, spacing: { before: 160, after: 20 }, children: [new TextRun({ text: label, bold: true, font: SERIF, size: 21 })] }),
  new Paragraph({ keepNext: true, spacing: { after: 80 }, children: [new TextRun({ text: title, italics: true, font: SERIF, size: 21 })] }),
];
const ch = [
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [new TextRun({ text: "UNIVERSIDAD PRIVADA DE TACNA · FACULTAD DE INGENIERÍA · ESCUELA PROFESIONAL DE INGENIERÍA DE SISTEMAS", font: SANS, size: 17, color: "444444" })] }),
  new Paragraph({ heading: HeadingLevel.TITLE, alignment: AlignmentType.CENTER, spacing: { after: 160 }, border: { bottom: { style: BorderStyle.SINGLE, size: 14, color: NAVY, space: 8 } }, children: [new TextRun({ text: J.title, bold: true, font: SERIF, size: 34, color: "141B34" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 }, children: [new TextRun({ text: "Autores: ", bold: true, font: SANS, size: 17 }), new TextRun({ text: J.authors.join(" · "), font: SANS, size: 17 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [new TextRun({ text: "Curso: ", bold: true, font: SANS, size: 17 }), new TextRun({ text: "SI-985 Seguridad de Tecnología de Información  |  Docente: Dr. Renzo Alberto Taco Coayla  |  Unidad II: Diseño de la solución tecnológica  |  Tacna, 2026", font: SANS, size: 17 })] }),
];
let kw = false, seenP = 0;
J.blocks.forEach((b, idx) => {
  if (b.k === "h1") ch.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: b.t })] }));
  else if (b.k === "h2") ch.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun({ text: b.t })] }));
  else if (b.k === "p") {
    ch.push(p(b.r));
    seenP++;
    if (seenP === 2 && !kw) { kw = true; ch.push(new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 130, line: 340 }, children: [new TextRun({ text: "Palabras clave: ", bold: true, font: SERIF, size: 21 }), new TextRun({ text: J.keywords, font: SERIF, size: 21 })] })); }
  }
  else if (b.k === "li") ch.push(new Paragraph({ numbering: { reference: "b", level: 0 }, alignment: AlignmentType.JUSTIFIED, spacing: { after: 70, line: 320 }, children: b.r.map(r => run(r)) }));
  else if (b.k === "tab") { ch.push(...cap(`Tabla ${b.n}`, b.title), table(b), nota(b.note)); }
  else if (b.k === "fig") {
    const w = 640, h = Math.round(w * b.h / b.w);
    ch.push(...cap(`Figura ${b.n}`, b.title), new Paragraph({ keepNext: true, alignment: AlignmentType.CENTER, children: [new ImageRun({ type: "png", data: fs.readFileSync(path.join(fig, b.file)), transformation: { width: w, height: h }, altText: { title: `Figura ${b.n}`, description: b.title, name: `Figura ${b.n}` } })] }), nota(b.note));
  }
});
ch.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: J.ref_head })] }));
J.refs.forEach(rr => ch.push(new Paragraph({ indent: { left: 720, hanging: 720 }, alignment: AlignmentType.LEFT, spacing: { after: 0, line: 480 }, children: rr.map(r => r.u ? new ExternalHyperlink({ link: r.t, children: [new TextRun({ text: r.t, font: SERIF, size: 20, color: NAVY, underline: {} })] }) : new TextRun({ text: r.t, italics: r.i, font: SERIF, size: 20 })) })));
{
  const W2 = [400, 1400, 2100, 2800, 450, 740, 500, 440, 808];
  const s2 = W2.reduce((a, b) => a + b, 0); W2[3] += W - s2;
  ch.push(new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, children: [new TextRun({ text: "ANEXO B. DATOS DE REGISTRO DE LAS REFERENCIAS" })] }));
  ch.push(new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text: "Consulta realizada el 10 de noviembre de 2026 en Crossref, DataCite y los sitios indicados.", font: SERIF, size: 19 })] }));
  const cell = (kids, w, head) => new TableCell({ width: { size: w, type: WidthType.DXA }, borders, margins: { top: 20, bottom: 20, left: 40, right: 40 }, shading: head ? { type: ShadingType.CLEAR, fill: "EEF2F9", color: "auto" } : undefined, children: [new Paragraph({ spacing: { after: 0, line: 200 }, children: kids })] });
  ch.push(new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: W2, rows: [
    new TableRow({ tableHeader: true, children: J.annex_head.map((h, i) => cell([new TextRun({ text: h, bold: true, font: SANS, size: 13 })], W2[i], true)) }),
    ...J.annex.map(r => new TableRow({ cantSplit: true, children: r.map((v, i) => cell([i === 2 && String(v).startsWith("http") ? new ExternalHyperlink({ link: v, children: [new TextRun({ text: v, font: SANS, size: 12, color: NAVY, underline: {} })] }) : new TextRun({ text: String(v), font: SANS, size: 12 })], W2[i], false)) })),
  ] }));
}
const footer = new Footer({ children: [new Paragraph({ tabStops: [{ type: TabStopType.RIGHT, position: W }], border: { top: { style: BorderStyle.SINGLE, size: 4, color: "D0D4DE", space: 6 } },
  children: [new TextRun({ text: "Monitoreo distribuido con Wazuh en cuatro servidores", font: SANS, size: 16, color: "6B6B6B" }), new TextRun({ text: "\tDocumento técnico - Unidad II - Página ", font: SANS, size: 16, color: "6B6B6B" }), new TextRun({ children: [PageNumber.CURRENT], font: SANS, size: 16, color: "6B6B6B" })] })] });
const doc = new Document({
  creator: J.authors.join("; "), title: J.title, description: "Documento técnico de la Unidad II",
  styles: { default: { document: { run: { font: SERIF, size: 21 } },
    title: { run: { font: SERIF, size: 34, bold: true }, paragraph: { spacing: { before: 0, after: 160 }, keepNext: true } },
    heading1: { run: { font: SERIF, size: 27, bold: true, color: NAVY }, paragraph: { spacing: { before: 300, after: 120 }, keepNext: true, border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "CFD6E4", space: 3 } } } },
    heading2: { run: { font: SERIF, size: 23, bold: true, color: "1B1B1B" }, paragraph: { spacing: { before: 200, after: 80 }, keepNext: true } } } },
  numbering: { config: [{ reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 340, hanging: 220 } } } }] }] },
  sections: [{ properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1190, bottom: 1080, left: 1134, right: 1134 } } }, footers: { default: footer }, children: ch }],
});
Packer.toBuffer(doc).then(b => { fs.writeFileSync(path.join(dir, "Articulo_Wazuh_Cuatro_Servidores.docx"), b); console.log("docx", b.length); });
