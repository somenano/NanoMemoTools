var expect        = require("chai").expect;
var NanoMemoTools = require("../index");

describe("NanoMemoTools.tools", function() {
    const seed = 'B1D17D48CB4F605EEAE7940D2FD9EC205D8B290C9822BE610A821C9D148BE332';
    let accounts = [
        {
            private_key: NanoMemoTools.tools.getPrivateKey(seed, 0),
            public_key: NanoMemoTools.tools.getPublicKeyFromPrivateKey(NanoMemoTools.tools.getPrivateKey(seed, 0))
        },
        {
            private_key: NanoMemoTools.tools.getPrivateKey(seed, 1),
            public_key: NanoMemoTools.tools.getPublicKeyFromPrivateKey(NanoMemoTools.tools.getPrivateKey(seed, 1))
        }
    ];
    accounts[0].address = NanoMemoTools.tools.getAddress(accounts[0].public_key);
    accounts[1].address = NanoMemoTools.tools.getAddress(accounts[1].public_key);
    const message = 'test message';
    const hash = '0000000000000000000000000000000000000000000000000000000000000000';

    describe("Data derivations", function() {
        it("Converts a seed and index to private key", function() {
            expect(accounts[0].private_key).to.equal('267AD5032FB8F2D2525BAA829E06E6EBD219EE3D8CF8946BABC75BB093E2C70D');
        });

        it("Converts a private key to a public key", function() {
            expect(accounts[0].public_key).to.equal('0326C7DB276F8D94BBAECD618BF0D05421F46BD436D83832DA0739EC2C5C2F87');
        });

        it ("Converts an address to a public key", function() {
            expect(NanoMemoTools.tools.getPublicKeyFromAddress(accounts[0].address)).to.equal(accounts[0].public_key);
        });

        it("Converts a public key to an address", function() {
            expect(accounts[0].address).to.equal('nano_11s8rzfkguwfkkxtxmd3jhrf1o33yjoxafpr91sfn3ssxip7rdw9dh8pqau4');
        });
    });

    describe("Data signging", function() {
        it("Signs data", function() {
            const signature = NanoMemoTools.tools.sign(message+hash, accounts[0].private_key);
            expect(signature).to.equal('fa6fa88a88225ef3165f28e2a8220ae739bbd2847ed6261d0f37d50de737285466d3caa0916bdc0dca1ecdef5860a19588eb9666438e517111e3f70570cea80f');
        });
    
        it("Verify a signature", function() {
            const signature = 'fa6fa88a88225ef3165f28e2a8220ae739bbd2847ed6261d0f37d50de737285466d3caa0916bdc0dca1ecdef5860a19588eb9666438e517111e3f70570cea80f';
            const valid = NanoMemoTools.tools.verify(message+hash, accounts[0].public_key, signature);
            expect(valid).to.equal(true);
        });
    });

    describe("Data encryption", function() {
        it("Encrypts and decrypts data", async function() {
            const cipher_text = NanoMemoTools.tools.encryptMessage(message, hash, accounts[1].public_key, accounts[0].private_key);
            const decrypted_text = NanoMemoTools.tools.decryptMessage(cipher_text, hash, accounts[0].public_key, accounts[1].private_key);
            expect(decrypted_text).to.equal(message);
        });
    });

});

describe("NanoMemoTools.memo", function() {

    const seed = 'B1D17D48CB4F605EEAE7940D2FD9EC205D8B290C9822BE610A821C9D148BE332';
    let accounts = [
        {
            private_key: NanoMemoTools.tools.getPrivateKey(seed, 0),
            public_key: NanoMemoTools.tools.getPublicKeyFromPrivateKey(NanoMemoTools.tools.getPrivateKey(seed, 0))
        },
        {
            private_key: NanoMemoTools.tools.getPrivateKey(seed, 1),
            public_key: NanoMemoTools.tools.getPublicKeyFromPrivateKey(NanoMemoTools.tools.getPrivateKey(seed, 1))
        }
    ];
    accounts[0].address = NanoMemoTools.tools.getAddress(accounts[0].public_key);
    accounts[1].address = NanoMemoTools.tools.getAddress(accounts[1].public_key);
    const message = 'test message';
    const encrypted_message = 'de9c1d129cd3997d97224414af26962ccf31e7fb383743c8e57ec3d3';   // accounts[0] -> accounts[1]
    const hash = '0000000000000000000000000000000000000000000000000000000000000000';
    const signature = 'fa6fa88a88225ef3165f28e2a8220ae739bbd2847ed6261d0f37d50de737285466d3caa0916bdc0dca1ecdef5860a19588eb9666438e517111e3f70570cea80f';
    const encrypted_signature = '1840bdfda94f8c0170aea0bccfef8b46228426a329c0b1742d21178f5282dfc79d5a5a4be65fc709fe37d9345702ed34f8885db8cccb2c9dbb4458fce6964804'; // accounts[0] -> accounts[1]

    describe("Data validations", function() {
        
        it("Validates addresses", function() {
            expect(NanoMemoTools.memo.validateAddress(accounts[0].address)).to.equal(true);     // Good address
            expect(NanoMemoTools.memo.validateAddress(accounts[0].address + 'a')).to.equal(false);  // Wrong length
            expect(NanoMemoTools.memo.validateAddress('nano_1111111111111111111111111111111111111111111111111111hifc8np1')).to.equal(false);    // Invalid checksum
        });
        
        it("Validates hashes", function() {
            expect(NanoMemoTools.memo.validateHash(hash)).to.equal(true);
            expect(NanoMemoTools.memo.validateHash('0')).to.equal(false);
        });
        
        it("Validates keys", function() {
            expect(NanoMemoTools.memo.validateKey(accounts[0].private_key)).to.equal(true);
            expect(NanoMemoTools.memo.validateKey(accounts[0].public_key)).to.equal(true);
            expect(NanoMemoTools.memo.validateKey('0')).to.equal(false);
        });
        
        it("Validates message", function() {
            expect(NanoMemoTools.memo.validateMessage(message)).to.equal(message);
        });
        
        it("Validates signature", function() {
            expect(NanoMemoTools.memo.validateSignature(signature)).to.equal(true);
            expect(NanoMemoTools.memo.validateSignature('0')).to.equal(false);
        });
    });

    describe("Memo Class", function() {
        it("Creates a valid Memo object without signature", function() {
            const memo = new NanoMemoTools.memo.Memo(hash, message, accounts[0].address);
            expect(memo.hash).to.equal(hash);
            expect(memo.message).to.equal(message);
            expect(memo.signing_address).to.equal(accounts[0].address);
            expect(memo.signature).to.equal(undefined);
            expect(memo.valid_signature).to.equal(false);
            const sig = memo.sign(accounts[0].private_key);
            expect(sig).to.equal(signature);
            expect(memo.signature).to.equal(sig);
            expect(memo.valid_signature).to.equal(true);
            memo.message = memo.message+'1234';
            expect(memo.valid_signature).to.equal(false);
        });

        it("Creates a valid Memo object with signature", function() {
            const memo = new NanoMemoTools.memo.Memo(hash, message, accounts[0].address, signature);
            expect(memo.hash).to.equal(hash);
            expect(memo.message).to.equal(message);
            expect(memo.signing_address).to.equal(accounts[0].address);
            expect(memo.signature).to.equal(signature);
            expect(memo.valid_signature).to.equal(true);
        });

        it("Creates a valid EncryptedMemo object without signature", function() {
            const encrypted_memo = new NanoMemoTools.memo.EncryptedMemo(hash, encrypted_message, accounts[0].address, accounts[1].address);
            expect(encrypted_memo.hash).to.equal(hash);
            expect(encrypted_memo.message).to.equal(encrypted_message);
            expect(encrypted_memo.signing_address).to.equal(accounts[0].address);
            expect(encrypted_memo.decrypting_address).to.equal(accounts[1].address);
            expect(encrypted_memo.signature).to.equal(undefined);
            expect(encrypted_memo.valid_signature).to.equal(false);
            const sig = encrypted_memo.sign(accounts[0].private_key);
            expect(sig).to.equal(encrypted_signature);
            expect(encrypted_memo.signature).to.equal(sig);
            expect(encrypted_memo.valid_signature).to.equal(true);
            encrypted_memo.message = encrypted_memo.message+'1234';
            expect(encrypted_memo.valid_signature).to.equal(false);
        });

        it("Creates a valid EncryptedMemo object with signature", function() {
            const encrypted_memo = new NanoMemoTools.memo.EncryptedMemo(hash, encrypted_message, accounts[0].address, accounts[1].address, encrypted_signature);
            expect(encrypted_memo.hash).to.equal(hash);
            expect(encrypted_memo.message).to.equal(encrypted_message);
            expect(encrypted_memo.signing_address).to.equal(accounts[0].address);
            expect(encrypted_memo.decrypting_address).to.equal(accounts[1].address);
            expect(encrypted_memo.signature).to.equal(encrypted_signature);
            expect(encrypted_memo.valid_signature).to.equal(true);
        });

        it("Converts a Memo to an EncryptedMemo", function() {
            const memo = new NanoMemoTools.memo.Memo(hash, message, accounts[0].address, signature);
            const encrypted_memo = NanoMemoTools.memo.encrypt(memo, accounts[0].private_key, accounts[1].address);
            expect(encrypted_memo.hash).to.equal(memo.hash);
            expect(encrypted_memo.message).to.equal(encrypted_message);
            expect(encrypted_memo.signing_address).to.equal(memo.signing_address);
            expect(encrypted_memo.signature).to.equal(undefined);
            expect(encrypted_memo.valid_signature).to.equal(false);
            const sig = encrypted_memo.sign(accounts[0].private_key);
            expect(sig).to.equal(encrypted_signature);
            expect(encrypted_memo.signature).to.equal(sig);
            expect(encrypted_memo.valid_signature).to.equal(true);
        });

        it("Converts an EncryptedMemo to a Memo", function() {
            const encrypted_memo = new NanoMemoTools.memo.EncryptedMemo(hash, encrypted_message, accounts[0].address, accounts[1].address, encrypted_signature);
            const memo = NanoMemoTools.memo.decrypt(encrypted_memo, accounts[1].private_key);
            expect(memo.hash).to.equal(encrypted_memo.hash);
            expect(memo.message).to.equal(message);
            expect(memo.signing_address).to.equal(encrypted_memo.signing_address);
            expect(memo.signature).to.equal(undefined);
            expect(memo.valid_signature).to.equal(false);
            const sig = memo.sign(accounts[0].private_key);
            expect(sig).to.equal(signature);
            expect(memo.signature).to.equal(sig);
            expect(memo.valid_signature).to.equal(true);
        });
    });
});
