const { mnemonicToEntropy } = require("ethereum-cryptography/bip39");
const { wordlist } = require("ethereum-cryptography/bip39/wordlists/english");
const { HDKey } = require("ethereum-cryptography/hdkey");
const { keccak256 } = require("ethereum-cryptography/keccak");
const { getPublicKey } = require("ethereum-cryptography/secp256k1");
const { bytesToHex } = require("ethereum-cryptography/utils");
const { writeFileSync } = require("fs");

function _store(_privateKey, _publicKey, _address) {
  const accountOne = {
    privateKey: _privateKey,
    publicKey: _publicKey,
    address: _address,
  };

  const accountOneData = JSON.stringify(accountOne);
  writeFileSync("account.json", accountOneData);
}
async function main(_mnemonic) {
  const entropy = mnemonicToEntropy(_mnemonic, wordlist);
  const private_key = HDKey.fromMasterSeed(entropy).deriveChild(0).privateKey;
  const publicKey = getPublicKey(private_key);
  const address = keccak256(publicKey).slice(-20);
  console.log(`Account One Wallet Address: 0x${bytesToHex(address)}`);
  _store(private_key, publicKey, address);
}
main(process.argv[2])
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
