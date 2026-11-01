"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");
const zlib = require("zlib");
const pth = require("path");
const fs = require("fs");
const os = require("os");
const rimraf = require("rimraf");
const crc32 = require("../util").crc32;

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid unless `validCrc` is given) payload.
function craftBomb(declaredSize, method, content, validCrc) {
    const name = Buffer.from("a");
    const crc = validCrc || 0; // deliberately wrong by default: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });

    // The RSS checks above depend on the OS committing the pages of a huge
    // Buffer.alloc. The checks below observe the allocation request itself:
    // Buffer.alloc is wrapped so that any request above ALLOC_LIMIT is recorded
    // and refused (so the unpatched code fails fast instead of OOM-ing the
    // runner). The entries carry a valid crc and a real payload, so the only
    // thing wrong with them is the lying declared size.
    describe("allocation is bounded by the archive data, not the declared size", () => {
        const ALLOC_LIMIT = 64 * 1024 * 1024;
        const stored = Buffer.from("stored payload");
        const payload = Buffer.from("hello world ".repeat(1000));
        const deflated = zlib.deflateRawSync(payload);
        const storedBomb = () => new Zip(craftBomb(DECLARED, 0 /* STORED */, stored, crc32(stored)));
        const deflatedBomb = () => new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, deflated, crc32(payload)));

        let originalAlloc = null;
        let oversized = [];

        const guardAllocations = () => {
            originalAlloc = Buffer.alloc;
            oversized = [];
            const realAlloc = originalAlloc;
            Buffer.alloc = function (size) {
                if (typeof size === "number" && size > ALLOC_LIMIT) {
                    oversized.push(size);
                    throw new RangeError("refused oversized allocation of " + size + " bytes");
                }
                return realAlloc.apply(Buffer, arguments);
            };
        };
        const restoreAllocations = () => {
            if (originalAlloc) {
                Buffer.alloc = originalAlloc;
                originalAlloc = null;
            }
        };
        const expectNoOversizedAllocation = () => {
            expect(oversized, "no allocation may be sized from the declared uncompressed size").to.eql([]);
        };

        afterEach(restoreAllocations);

        it("sanity: an honest STORED entry built by the test helper reads back", () => {
            const zip = new Zip(craftBomb(stored.length, 0 /* STORED */, stored, crc32(stored)));
            expect(zip.getEntries()[0].getData().equals(stored)).to.equal(true);
        });

        it("getData of a STORED entry allocates only the stored bytes", () => {
            const zip = storedBomb();
            guardAllocations();
            let data;
            try {
                data = zip.getEntries()[0].getData();
            } finally {
                restoreAllocations();
            }
            expectNoOversizedAllocation();
            expect(data.equals(stored)).to.equal(true);
        });

        it("getData of a DEFLATED entry allocates only the inflated bytes", () => {
            const zip = deflatedBomb();
            guardAllocations();
            let data;
            try {
                data = zip.getEntries()[0].getData();
            } finally {
                restoreAllocations();
            }
            expectNoOversizedAllocation();
            expect(data.equals(payload)).to.equal(true);
        });

        it("getData of a STORED entry with a bad crc fails on the crc, not on the declared size", () => {
            const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
            guardAllocations();
            try {
                expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
            } finally {
                restoreAllocations();
            }
            expectNoOversizedAllocation();
        });

        it("getData of a malformed DEFLATED entry fails without sizing a buffer from the declared size", () => {
            const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
            guardAllocations();
            try {
                expect(() => zip.getEntries()[0].getData()).to.throw();
            } finally {
                restoreAllocations();
            }
            expectNoOversizedAllocation();
        });

        it("readFile, readAsText and test() do not allocate the declared size", () => {
            const zipStored = storedBomb();
            const zipDeflated = deflatedBomb();
            guardAllocations();
            let readStored, readDeflated, text, testedStored, testedDeflated;
            try {
                readStored = zipStored.readFile("a");
                readDeflated = zipDeflated.readFile("a");
                text = zipDeflated.readAsText("a");
                testedStored = zipStored.test();
                testedDeflated = zipDeflated.test();
            } finally {
                restoreAllocations();
            }
            expectNoOversizedAllocation();
            expect(readStored.equals(stored)).to.equal(true);
            expect(readDeflated.equals(payload)).to.equal(true);
            expect(text).to.equal(payload.toString());
            expect(testedStored).to.equal(true);
            expect(testedDeflated).to.equal(true);
        });

        it("extractAllTo does not allocate the declared size", () => {
            const zip = deflatedBomb();
            const target = pth.join(os.tmpdir(), "adm-zip-cve-2026-39244-sync-" + process.pid);
            guardAllocations();
            try {
                zip.extractAllTo(target, true);
            } finally {
                restoreAllocations();
                try {
                    expectNoOversizedAllocation();
                    expect(fs.readFileSync(pth.join(target, "a")).equals(payload)).to.equal(true);
                } finally {
                    rimraf.sync(target);
                }
            }
        });

        it("getDataAsync of a STORED entry allocates only the stored bytes", (done) => {
            const zip = storedBomb();
            guardAllocations();
            try {
                zip.getEntries()[0].getDataAsync((data, err) => {
                    restoreAllocations();
                    try {
                        expectNoOversizedAllocation();
                        expect(err).to.equal(undefined);
                        expect(data.equals(stored)).to.equal(true);
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
            } catch (e) {
                restoreAllocations();
                done(e);
            }
        });

        it("getDataAsync of a DEFLATED entry allocates only the inflated bytes", (done) => {
            const zip = deflatedBomb();
            guardAllocations();
            try {
                zip.getEntries()[0].getDataAsync((data, err) => {
                    restoreAllocations();
                    try {
                        expectNoOversizedAllocation();
                        expect(err).to.equal(undefined);
                        expect(data.equals(payload)).to.equal(true);
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
            } catch (e) {
                restoreAllocations();
                done(e);
            }
        });

        it("readFileAsync and extractAllToAsync do not allocate the declared size", (done) => {
            const zip = deflatedBomb();
            const target = pth.join(os.tmpdir(), "adm-zip-cve-2026-39244-async-" + process.pid);
            const finish = (e) => {
                restoreAllocations();
                rimraf.sync(target);
                done(e);
            };
            guardAllocations();
            try {
                zip.readFileAsync("a", (data, err) => {
                    try {
                        expectNoOversizedAllocation();
                        expect(err).to.equal(undefined);
                        expect(data.equals(payload)).to.equal(true);
                    } catch (e) {
                        return finish(e);
                    }
                    try {
                        zip.extractAllToAsync(target, true, false, (err_1) => {
                            try {
                                expectNoOversizedAllocation();
                                expect(err_1).to.equal(undefined);
                                expect(fs.readFileSync(pth.join(target, "a")).equals(payload)).to.equal(true);
                                finish();
                            } catch (e) {
                                finish(e);
                            }
                        });
                    } catch (e) {
                        finish(e);
                    }
                });
            } catch (e) {
                finish(e);
            }
        });
    });
});
