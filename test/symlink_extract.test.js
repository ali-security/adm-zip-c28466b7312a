"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");
const Utils = require("../util/utils");
const pth = require("path");
const fs = require("fs");
const os = require("os");
const rimraf = require("rimraf");

// Regression test for CVE-2026-76845 (symlink attack on extraction):
// sanitize() only proves that the textual output path stays inside the target
// directory. When a component of that path already exists on disk as a symlink
// (or a Windows junction) pointing outside the target, mkdir()/open() follow it
// and the archive content lands outside the extraction root. Extraction now
// refuses to create or write anything through such a symlink.

describe("adm-zip - symlink in extraction target - CVE-2026-76845", function () {
    const base = pth.join(os.tmpdir(), "adm-zip-cve-2026-76845-" + process.pid);
    const target = pth.join(base, "target");
    const outside = pth.join(base, "outside");
    const inTheWay = /There is a file in the way/;

    beforeEach(() => {
        rimraf.sync(base);
        fs.mkdirSync(target, { recursive: true });
        fs.mkdirSync(outside, { recursive: true });
    });

    after(() => {
        rimraf.sync(base);
    });

    // target/<name> -> outside (directory link; a junction on Windows needs no privilege)
    function linkDirOutside(ctx, name) {
        const link = pth.join(target, name);
        try {
            fs.symlinkSync(outside, link, "junction");
        } catch (e) {
            ctx.skip(); // symlinks unsupported here (e.g. EPERM on Windows)
        }
        return link;
    }

    // target/<name> -> outside/<dest> (file link; may need privilege on Windows)
    function linkFileOutside(ctx, name, dest) {
        const link = pth.join(target, name);
        try {
            fs.symlinkSync(pth.join(outside, dest), link, "file");
        } catch (e) {
            ctx.skip(); // symlinks unsupported here (e.g. EPERM on Windows)
        }
        return link;
    }

    function archive(entries) {
        const zip = new Zip();
        for (const name of Object.keys(entries)) {
            zip.addFile(name, entries[name] === null ? null : Buffer.from(entries[name]));
        }
        return new Zip(zip.toBuffer());
    }

    function outsideList() {
        return fs.readdirSync(outside).sort();
    }

    describe("extractAllTo()", () => {
        it("does not write a file through a symlinked directory", function () {
            linkDirOutside(this, "evil");
            const zip = archive({ "evil/payload.txt": "pwned" });

            expect(() => zip.extractAllTo(target, true)).to.throw(inTheWay);
            expect(fs.existsSync(pth.join(outside, "payload.txt"))).to.equal(false);
            expect(outsideList()).to.deep.equal([]);
        });

        it("does not create a directory through a symlinked directory", function () {
            linkDirOutside(this, "evil");
            const zip = archive({ "evil/sub/": null });

            expect(() => zip.extractAllTo(target, true)).to.throw(inTheWay);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
            expect(outsideList()).to.deep.equal([]);
        });

        it("does not create a file through a dangling symlink (overwrite=false)", function () {
            linkFileOutside(this, "payload.txt", "created.txt");
            const zip = archive({ "payload.txt": "pwned" });

            expect(() => zip.extractAllTo(target, false)).to.throw(inTheWay);
            expect(fs.existsSync(pth.join(outside, "created.txt"))).to.equal(false);
        });

        it("does not overwrite a file through a symlink (overwrite=true)", function () {
            fs.writeFileSync(pth.join(outside, "secret.txt"), "original");
            linkFileOutside(this, "payload.txt", "secret.txt");
            const zip = archive({ "payload.txt": "pwned" });

            expect(() => zip.extractAllTo(target, true)).to.throw(inTheWay);
            expect(fs.readFileSync(pth.join(outside, "secret.txt"), "utf8")).to.equal("original");
        });
    });

    describe("extractEntryTo()", () => {
        it("does not write a single file through a symlinked directory", function () {
            linkDirOutside(this, "evil");
            const zip = archive({ "evil/payload.txt": "pwned" });

            expect(() => zip.extractEntryTo("evil/payload.txt", target, true, true)).to.throw(inTheWay);
            expect(outsideList()).to.deep.equal([]);
        });

        it("does not write a single file through a symlink given as outFileName", function () {
            linkDirOutside(this, "evil");
            const zip = archive({ "payload.txt": "pwned" });

            expect(() => zip.extractEntryTo("payload.txt", target, false, true, false, "evil/renamed.txt")).to.throw(inTheWay);
            expect(outsideList()).to.deep.equal([]);
        });

        it("does not overwrite a single file through a symlink", function () {
            fs.writeFileSync(pth.join(outside, "secret.txt"), "original");
            linkFileOutside(this, "payload.txt", "secret.txt");
            const zip = archive({ "payload.txt": "pwned" });

            expect(() => zip.extractEntryTo("payload.txt", target, false, true)).to.throw(inTheWay);
            expect(fs.readFileSync(pth.join(outside, "secret.txt"), "utf8")).to.equal("original");
        });

        it("does not write directory children through a symlinked directory", function () {
            linkDirOutside(this, "dir");
            const zip = archive({ "dir/": null, "dir/payload.txt": "pwned" });

            expect(() => zip.extractEntryTo("dir/", target, true, true)).to.throw(inTheWay);
            expect(outsideList()).to.deep.equal([]);
        });
    });

    describe("extractAllToAsync()", () => {
        it("does not write a file through a symlinked directory [callback]", function (done) {
            linkDirOutside(this, "evil");
            const zip = archive({ "evil/payload.txt": "pwned" });
            let called = false;

            zip.extractAllToAsync(target, true, false, (err) => {
                if (called) return;
                called = true;
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(inTheWay);
                    expect(outsideList()).to.deep.equal([]);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("does not write a file through a symlinked directory [Promise]", function () {
            linkDirOutside(this, "evil");
            const zip = archive({ "evil/payload.txt": "pwned" });

            return zip.extractAllToAsync(target, true, false).then(
                () => {
                    throw new Error("extraction through a symlink was not rejected");
                },
                (err) => {
                    expect(err.message).to.match(inTheWay);
                    expect(outsideList()).to.deep.equal([]);
                }
            );
        });

        it("does not create a directory through a symlinked directory [Promise]", function () {
            linkDirOutside(this, "evil");
            const zip = archive({ "evil/sub/": null });

            return zip.extractAllToAsync(target, true, false).then(
                () => {
                    throw new Error("directory creation through a symlink was not rejected");
                },
                (err) => {
                    expect(err.message).to.match(/Unable to create folder/);
                    expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
                    expect(outsideList()).to.deep.equal([]);
                }
            );
        });

        it("does not overwrite a file through a symlink [Promise]", function () {
            fs.writeFileSync(pth.join(outside, "secret.txt"), "original");
            linkFileOutside(this, "payload.txt", "secret.txt");
            const zip = archive({ "payload.txt": "pwned" });

            return zip.extractAllToAsync(target, true, false).then(
                () => {
                    throw new Error("overwrite through a symlink was not rejected");
                },
                (err) => {
                    expect(err.message).to.match(inTheWay);
                    expect(fs.readFileSync(pth.join(outside, "secret.txt"), "utf8")).to.equal("original");
                }
            );
        });
    });

    describe("legitimate extraction", () => {
        it("still extracts into a plain target directory", function () {
            const zip = archive({ "a/b/c.txt": "ok", "d.txt": "ok2" });
            zip.extractAllTo(target, true);
            zip.extractEntryTo("d.txt", pth.join(target, "single"), false, true);

            expect(fs.readFileSync(pth.join(target, "a", "b", "c.txt"), "utf8")).to.equal("ok");
            expect(fs.readFileSync(pth.join(target, "d.txt"), "utf8")).to.equal("ok2");
            expect(fs.readFileSync(pth.join(target, "single", "d.txt"), "utf8")).to.equal("ok2");
        });

        it("still extracts when the target root itself is reached through a symlink", function () {
            const linkedRoot = pth.join(base, "linked-root");
            try {
                fs.symlinkSync(target, linkedRoot, "junction");
            } catch (e) {
                this.skip();
            }
            const zip = archive({ "a/b/c.txt": "ok" });
            zip.extractAllTo(linkedRoot, true);
            zip.extractEntryTo("a/b/c.txt", pth.join(linkedRoot, "single"), false, true);

            expect(fs.readFileSync(pth.join(target, "a", "b", "c.txt"), "utf8")).to.equal("ok");
            expect(fs.readFileSync(pth.join(target, "single", "c.txt"), "utf8")).to.equal("ok");

            return zip.extractAllToAsync(pth.join(linkedRoot, "async"), true, false).then(() => {
                expect(fs.readFileSync(pth.join(target, "async", "a", "b", "c.txt"), "utf8")).to.equal("ok");
            });
        });
    });

    describe("Utils.assertPathSafe()", () => {
        it("rejects a symlinked component below the root", function () {
            linkDirOutside(this, "evil");
            const utils = new Utils();
            expect(() => utils.assertPathSafe(target, pth.join(target, "evil", "x", "y.txt"))).to.throw(inTheWay);
        });

        it("accepts the root itself, missing paths and paths outside the root", () => {
            const utils = new Utils();
            expect(() => utils.assertPathSafe(target, target)).to.not.throw();
            expect(() => utils.assertPathSafe(target, pth.join(target, "missing", "file.txt"))).to.not.throw();
            expect(() => utils.assertPathSafe(target, outside)).to.not.throw();
        });

        it("is a no-op for a custom fs without lstatSync", function () {
            linkDirOutside(this, "evil");
            // a minimal custom filesystem (Utils only requires statSync to accept it)
            const customFs = { statSync: fs.statSync.bind(fs) };
            const utils = new Utils({ fs: customFs });
            expect(utils.fs).to.equal(customFs);
            expect(() => utils.assertPathSafe(target, pth.join(target, "evil", "y.txt"))).to.not.throw();
        });
    });
});
