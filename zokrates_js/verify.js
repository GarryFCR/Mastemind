const { initialize } = require('zokrates-js/node');
const fs = require('fs')

const  program  = require('./program.json')


initialize().then((zokratesProvider) => {
    
    obj = Object.values(program.program);
    array= new Uint8Array(obj)
    
    const artifacts = {
       program : array,
       abi : program.abi
    }
   console.log(artifacts)

   
});