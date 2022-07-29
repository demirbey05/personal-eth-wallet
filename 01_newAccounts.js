const {
  generateMnemonic,
  mnemonicToEntropy,
} = require("ethereum-cryptography/bip39");
const { wordlist } = require("ethereum-cryptography/bip39/wordlists/english");
const { HDKey } = require("ethereum-cryptography/hdkey");
const { getPublicKey } = require("ethereum-cryptography/secp256k1");
const { bytesToHex } = require("ethereum-cryptography/utils");
const { keccak256 } = require("ethereum-cryptography/keccak");

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

function _generateMnemonic() {
  const strength = 256;
  const mnemonic = generateMnemonic(wordlist, strength);
  const entropy = mnemonicToEntropy(mnemonic, wordlist);
  return { mnemonic, entropy };
}

function _getHdRootKey(_mnemonic) {
  return HDKey.fromMasterSeed(_mnemonic);
}

function _generatePrivateKey(_hdRootKey, _accountIndex) {
  return _hdRootKey.deriveChild(_accountIndex).privateKey;
}

function _getPublicKey(_privateKey) {
  return getPublicKey(_privateKey);
}

function _getEthAddress(_publicKey) {
  return keccak256(_publicKey).slice(-20);
}

async function main() {
  const { mnemonic, entropy } = _generateMnemonic();
  console.log(`WARNING! Never disclose your Seed Phrase:\n ${mnemonic}`);
  const hdRootKey = _getHdRootKey(entropy);
  const privateKey = _generatePrivateKey(hdRootKey, 0);
  const publicKey = _getPublicKey(privateKey);
  const eth_address = _getEthAddress(publicKey);
  console.log(`Account One Wallet Address: 0x${bytesToHex(eth_address)}`);

  _store(privateKey, publicKey, eth_address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
