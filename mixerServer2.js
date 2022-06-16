const Constants = require('./constants')
const fs = require('fs')
const assert = require('assert')
const { bigInt } = require('snarkjs')
const crypto = require('crypto')
const circomlib = require('circomlib')
const merkleTree = require('fixed-merkle-tree')
const Web3 = require('web3')
const buildGroth16 = require('websnark/src/groth16')
const websnarkUtils = require('websnark/src/utils')
const { toWei } = require('web3-utils')

let web3, contract, netId, circuit, proving_key, groth16
const MERKLE_TREE_HEIGHT = 20
const RPC_URL = 'https://speedy-nodes-nyc.moralis.io/93e71caa8ab187deaacaf849/eth/goerli/archive'
const PRIVATE_KEY = '7869c6a785ce590b88c04c2cabdc404b3858c3d027161f0d0c21969ff2f7a257' // 0x94462e71A887756704f0fb1c0905264d487972fE
const CONTRACT_ADDRESS = '0x199d648Ffc99EcCdd852244F0173DD0BF5B0D6D2'
const AMOUNT = '0.1'

const rbigint = (nbytes) => bigInt.leBuff2int(crypto.randomBytes(nbytes))

const pedersenHash = (data) => circomlib.babyJub.unpackPoint(circomlib.pedersenHash.hash(data))[0]

const toHex = (number, length = 32) =>
    '0x' +
    (number instanceof Buffer ? number.toString('hex') : bigInt(number).toString(16)).padStart(length * 2, '0')

function createDeposit(nullifier, secret) {
    let deposit = { nullifier, secret }
    deposit.preimage = Buffer.concat([deposit.nullifier.leInt2Buff(31), deposit.secret.leInt2Buff(31)])
    deposit.commitment = pedersenHash(deposit.preimage)
    deposit.nullifierHash = pedersenHash(deposit.nullifier.leInt2Buff(31))
    return deposit
}

async function deposit() {
    const deposit = createDeposit(rbigint(31), rbigint(31))
    // console.log(deposit);
    console.log('Sending deposit transaction...')
    const tx = await contract.methods
        .deposit(toHex(deposit.commitment))
        .send({ value: toWei(AMOUNT), from: web3.eth.defaultAccount, gas: 2e6 })
    console.log(`https://kovan.etherscan.io/tx/${tx.transactionHash}`)

    return `cosmic-eth-${AMOUNT}-${netId}-${toHex(deposit.preimage, 62)}`
}

async function withdraw(note, recipient) {
    const deposit = parseNote(note)
    // console.log(deposit)
    const { proof, args } = await generateSnarkProof(deposit, recipient)
    console.log('Sending withdrawal transaction...')
    const tx = await contract.methods.withdraw(proof, ...args).send({ from: web3.eth.defaultAccount, gas: 1e6 })
    console.log(`https://kovan.etherscan.io/tx/${tx.transactionHash}`)
}

function parseNote(noteString) {
    const noteRegex = /cosmic-(?<currency>\w+)-(?<amount>[\d.]+)-(?<netId>\d+)-0x(?<note>[0-9a-fA-F]{124})/g
    const match = noteRegex.exec(noteString)

    const buf = Buffer.from(match.groups.note, 'hex')
    const nullifier = bigInt.leBuff2int(buf.slice(0, 31))
    const secret = bigInt.leBuff2int(buf.slice(31, 62))
    return createDeposit(nullifier, secret)
}

async function generateMerkleProof(deposit) {
    console.log('Getting contract state...')
    const events = await contract.getPastEvents('Deposit', { fromBlock: 0, toBlock: 'latest' })
    const leaves = events
        .sort((a, b) => a.returnValues.leafIndex - b.returnValues.leafIndex) // Sort events in chronological order
        .map((e) => e.returnValues.commitment)
    const tree = new merkleTree(MERKLE_TREE_HEIGHT, leaves)

    let depositEvent = events.find((e) => e.returnValues.commitment === toHex(deposit.commitment))
    let leafIndex = depositEvent ? depositEvent.returnValues.leafIndex : -1

    const isValidRoot = await contract.methods.isKnownRoot(toHex(tree.root())).call()
    const isSpent = await contract.methods.isSpent(toHex(deposit.nullifierHash)).call()
    assert(isValidRoot === true, 'Merkle tree is corrupted')
    assert(isSpent === false, 'The note is already spent')
    assert(leafIndex >= 0, 'The deposit is not found in the tree')

    const { pathElements, pathIndices } = tree.path(leafIndex)
    return { pathElements, pathIndices, root: tree.root() }
}

async function generateSnarkProof(deposit, recipient) {
    const { root, pathElements, pathIndices } = await generateMerkleProof(deposit)

    const input = {
        root: root,
        nullifierHash: deposit.nullifierHash,
        recipient: bigInt(recipient),
        relayer: 0,
        fee: 0,
        refund: 0,

        nullifier: deposit.nullifier,
        secret: deposit.secret,
        pathElements: pathElements,
        pathIndices: pathIndices,
    }

    console.log('Generating SNARK proof...')
    const proofData = await websnarkUtils.genWitnessAndProve(groth16, input, circuit, proving_key)
    const { proof } = websnarkUtils.toSolidityInput(proofData)

    const args = [
        toHex(input.root),
        toHex(input.nullifierHash),
        toHex(input.recipient, 20),
        toHex(input.relayer, 20),
        toHex(input.fee),
        toHex(input.refund),
    ]

    return { proof, args }
}

async function main() {
    web3 = new Web3(new Web3.providers.HttpProvider(RPC_URL, { timeout: 5 * 60 * 1000 }), null, {
        transactionConfirmationBlocks: 1,
    })
    circuit = require(__dirname + '/circuits/withdraw.json')
    proving_key = fs.readFileSync(__dirname + '/circuits/withdraw_proving_key.bin').buffer
    groth16 = await buildGroth16()
    netId = await web3.eth.net.getId()
    contract = new web3.eth.Contract(Constants.ABI.MIXER, CONTRACT_ADDRESS)
    const account = web3.eth.accounts.privateKeyToAccount('0x' + PRIVATE_KEY)
    web3.eth.accounts.wallet.add('0x' + PRIVATE_KEY)
    // eslint-disable-next-line require-atomic-updates
    web3.eth.defaultAccount = account.address

    const note = await deposit()
    console.log('Deposited note:', note)
    await withdraw(note, '0x79E19664E2227e7e4a6eC5C95281974837824207')
    console.log('Done')
    process.exit()
}

main()
