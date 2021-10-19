#!/bin/bash

npx hardhat test

# Enter the Guess [n1,n2,n3,n4]
echo "Enter your guess"
read -p "Enter first number  : " n1
read -p "Enter second number : " n2
read -p "Enter third number  : " n3
read -p "Enter fourth number : " n4

echo "Your Guess - [$n1,$n2,$n3,$n4]"

echo "{\"Guess\":[\"$n1\",\"$n2\",\"$n3\",\"$n4\"]}" > ./zokrates_js/pubGuess.json



node -e 'require("./zokrates_js/proof.js").proof()'

node -e 'require("./zokrates_js/verify.js").verify()'
