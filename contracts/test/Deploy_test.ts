// This script can be used to deploy the "Storage" contract using ethers.js library.
// Please make sure to compile "./contracts/1_Storage.sol" file before running this script.
// And use Right click -> "Run" from context menu of the file to run the script. Shortcut: Ctrl+Shift+S

(async function() {
  try {
    const metadata = JSON.parse(await remix.call('fileManager', 'getFile', 'artifacts/ECMath.json'))
    const metadata_Verifier = JSON.parse(await remix.call('fileManager', 'getFile', 'artifacts/MLSAGVerify.json'))
    // the variable web3Provider is a remix global variable object
    const signer = (new ethers.providers.Web3Provider(web3Provider)).getSigner()
    // Create an instance of a Contract Factory
    let factory = new ethers.ContractFactory(metadata.abi, metadata.data.bytecode.object, signer);
    let factory_Verfier = new ethers.ContractFactory(metadata_Verifier.abi, metadata_Verifier.data.bytecode.object, signer);
    let contract = await factory.deploy(256);
    console.log(contract.address);
    // The transaction that was sent to the network to deploy the Contract
    console.log(contract.deployTransaction.hash);
    // The contract is NOT deployed yet; we must wait until it is mined
    await contract.deployed()
    // Done! The contract is deployed.
    console.log('contract deployed')
    // Notice we pass the constructor's parameters here
    
    let verifier=await factory_Verfier.deploy(contract.address);
    console.log('verifier contract deploying')
    // The address the Contract WILL have once mined
    console.log(verifier.address);
    // The transaction that was sent to the network to deploy the Contract
    console.log(verifier.deployTransaction.hash);
    // The contract is NOT deployed yet; we must wait until it is mined
    await verifier.deployed()
    // Done! The contract is deployed.
    console.log('verifier contract deployed')
  } catch (e) {
    console.log(e.message)
  }
})()