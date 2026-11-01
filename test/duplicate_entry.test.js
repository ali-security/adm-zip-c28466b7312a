"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");
const pth = require("path");
const fs = require("fs");
const os = require("os");
const rimraf = require("rimraf");

// Regression test for GHSA-p634-w6r4-rjp2:
// a ZIP archive can declare two entries with the same name. adm-zip kept both
// in its entry list but only the last one in its name lookup table, so
// getEntry()/readFile() (table) and extractAllTo() (list) resolved the same name
// to different content. An application that validated an entry through
// getEntry() before extracting the whole archive could approve one file while
// another file's bytes were written to disk under that name. Such archives are
// now rejected when the central directory is read.

// Build an archive whose two entries are both named "b.txt": the first one
// carries "FIRST", the second "SECOND" (same technique as the advisory PoC).
function craftDuplicateZip() {
    const zip = new Zip({ noSort: true });
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    const buf = Buffer.from(zip.toBuffer());

    const from = Buffer.from("a.txt");
    const to = Buffer.from("b.txt");
    let renamed = 0;
    for (let i = buf.indexOf(from); i !== -1; i = buf.indexOf(from, i + from.length)) {
        to.copy(buf, i);
        renamed++;
    }
    // the name lives once in the local file header and once in the central directory
    expect(renamed).to.equal(2);
    return buf;
}

describe("ADM-ZIP - duplicate entry names - GHSA-p634-w6r4-rjp2", () => {
    const target = pth.join(os.tmpdir(), "adm-zip-ghsa-p634-w6r4-rjp2-" + process.pid);

    beforeEach(() => {
        rimraf.sync(target);
        fs.mkdirSync(target, { recursive: true });
    });

    after(() => {
        rimraf.sync(target);
    });

    it("rejects an archive with duplicate entry names on getEntry()", () => {
        const zip = new Zip(craftDuplicateZip());
        expect(() => zip.getEntry("b.txt")).to.throw(/Duplicate entry name/);
    });

    it("rejects an archive with duplicate entry names on readFile() and getEntries()", () => {
        expect(() => new Zip(craftDuplicateZip()).readFile("b.txt")).to.throw(/Duplicate entry name/);
        expect(() => new Zip(craftDuplicateZip()).getEntries()).to.throw(/Duplicate entry name/);
    });

    it("rejects an archive with duplicate entry names when entries are read on load", () => {
        expect(() => new Zip(craftDuplicateZip(), { readEntries: true })).to.throw(/Duplicate entry name/);
    });

    it("extractAllTo() rejects the archive and writes nothing to disk", () => {
        const zip = new Zip(craftDuplicateZip());
        expect(() => zip.extractAllTo(target, false)).to.throw(/Duplicate entry name/);
        expect(fs.existsSync(pth.join(target, "b.txt"))).to.equal(false);
        expect(fs.readdirSync(target)).to.have.lengthOf(0);
    });

    it("extractAllToAsync() rejects the archive and writes nothing to disk", () => {
        const zip = new Zip(craftDuplicateZip());
        return zip.extractAllToAsync(target, false, false).then(
            () => {
                throw new Error("extractAllToAsync should have rejected the archive");
            },
            (err) => {
                expect(err.message).to.match(/Duplicate entry name/);
                expect(fs.readdirSync(target)).to.have.lengthOf(0);
            }
        );
    });

    it("the validated entry and the extracted file never disagree (advisory PoC)", () => {
        // validate-then-extract workflow from the advisory: getEntry('b.txt') used to
        // return "SECOND" while extractAllTo wrote "FIRST" under the same name
        let checked = null;
        try {
            checked = new Zip(craftDuplicateZip()).getEntry("b.txt").getData().toString();
        } catch (e) {
            expect(e.message).to.match(/Duplicate entry name/);
        }
        let extracted = null;
        try {
            new Zip(craftDuplicateZip()).extractAllTo(target, false);
            extracted = fs.readFileSync(pth.join(target, "b.txt")).toString();
        } catch (e) {
            expect(e.message).to.match(/Duplicate entry name/);
        }
        expect(checked).to.equal(null);
        expect(extracted).to.equal(null);
    });

    it("still loads archives whose entry names match Object.prototype members", () => {
        const zip = new Zip();
        const names = ["__proto__", "constructor", "toString", "hasOwnProperty", "valueOf", "normal.txt"];
        for (const name of names) {
            zip.addFile(name, Buffer.from("content of " + name));
        }
        const reopened = new Zip(zip.toBuffer());
        expect(reopened.getEntries().map((e) => e.entryName).sort()).to.deep.equal(names.slice().sort());
        for (const name of names) {
            expect(reopened.readFile(name).toString()).to.equal("content of " + name);
        }
    });

    it("still loads and extracts an archive with distinct entry names", () => {
        const zip = new Zip();
        zip.addFile("a.txt", Buffer.from("FIRST"));
        zip.addFile("b.txt", Buffer.from("SECOND"));
        const reopened = new Zip(zip.toBuffer());
        expect(reopened.getEntry("b.txt").getData().toString()).to.equal("SECOND");
        reopened.extractAllTo(target, false);
        expect(fs.readFileSync(pth.join(target, "a.txt")).toString()).to.equal("FIRST");
        expect(fs.readFileSync(pth.join(target, "b.txt")).toString()).to.equal("SECOND");
    });
});
