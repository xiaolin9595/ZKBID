(async () => {
    try {
// a random address to send the tokens to

        const  CONTRACT_ADDR = '0x3fdF222e363C6907C99B965cCD594B78BC4D9A35'
        let hash='0x30a8ec89f40086308bcf85ba692982244ce1ed1782d0eee8f0ba1040a516c820'
        let i=[     "0x12505581a0634cc670da666a145189c11178554150f7b1188bf125be40eb96bd",     "0x1ebdbb19d79d58ae45dd212e1e8970e6faef910fb8253e99f64b6a012950bb31" ]
        let p=[   "0x0c86b098e2b51553d6fa957df79dd43fd0d16ca4e41461a5dfbd47d4a1221983",     "0x08e783017864288f28fd4526b74a826aa56501c1f33cccbca34f11ceaf2a1d73" ]
        let sigs=[     "0x1835b45bb269aa0ad73d43d1fdc5639fa12c42f5779e7912d1c2489518a64e6e",     "0x15762a01888c3bfdddc85993f486eded5ab28657167f0e0ddcea25059764b836" ]
        let pp=["0x0b07b946cd7d4bfb82d6caa0873612a3228d8905cea1b6bde620cdff9144b121",     "0x169d9e0c92d796fea6a1330f73b7e3f83223ad7e2b8516698366c04203330321"]
        let sigp=["0x109989d24f89f504ac4c6542aeb001b98ad22898ec7b851ef5ef21376c006d6"]
        console.log('start')
        
        const metadata = JSON.parse(await remix.call('fileManager', 'getFile', 'artifacts/MLSAGVerify.json'))
        
        // get the provider from metamask
        const provider = (new ethers.providers.Web3Provider(web3Provider))
        const signer = provider.getSigner()
        let contract = new ethers.Contract(CONTRACT_ADDR, metadata.abi, signer);
        let gasEstimate = await contract.estimateGas.VerifyMLSAG(hash, i, p, sigs);
        console.log('Estimated Gas:', gasEstimate.toString());
        let txn = await contract.VerifyMLSAG(hash,i,p,sigs)
        
        console.log(txn)

       p=p.concat(pp)
       sigs=sigs.concat(sigp)
        gasEstimate=await contract.estimateGas.VerifyMLSAG(hash, i, p, sigs);
        console.log('Estimated Gas:', gasEstimate.toString());
        txn = await contract.VerifyMLSAG(hash,i,p,sigs)
        console.log(txn)
        
     }catch (e) {
        console.log(e.message)
    }
})()