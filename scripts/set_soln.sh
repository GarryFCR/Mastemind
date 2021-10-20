#!/bin/bash



# Enter the Guess [n1,n2,n3,n4]
echo "Set the Secret Solution"
read -p "Enter first number  : " n1
read -p "Enter second number : " n2
read -p "Enter third number  : " n3
read -p "Enter fourth number : " n4

echo "Private Solution - [$n1,$n2,$n3,$n4]"

echo "{\"Solution\":[\"$n1\",\"$n2\",\"$n3\",\"$n4\"]}" > ./zokrates_js/privsoln.json

