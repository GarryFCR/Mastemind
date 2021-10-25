# Mastermind - A game using Zk-SNARKs(Zokrates)

## The rules of Mastermind

There are two players: the codebreaker and the codemaster.

The codemaster creates a secret four-digit sequence of coloured pegs, limited to red, blue, green, and yellow.

To win, the codebreaker must guess the secret sequence of pegs within a set number of attempts. After each guess, if the codebreaker does not yet have the correct solution, the codemaster must tell the codebreaker the following clue:

* How many exact matches of colour and position there are — these are are black pegs

* How many pegs have matching colours, but are in the wrong position — these are white pegs.

For example, if the solution is R R B Y, and the guess is Y R B G, the codemaster must provide this clue: 2 black pegs and 1 white peg.

> Solution       : Y R B G
   Guess          : R R B Y

Exact matches  : 0 1 1 0 -> 2 black pegs
Inexact matches: 0 0 0 1 -> 1 white peg
Inexact matches do not overlap; for instance:

> Solution       : R R Y B
   Guess          : G G R B

Exact matches  : 0 0 0 1 -> 1 black peg
Inexact matches: 0 0 1 0 -> 1 white peg (not two, even though there are two red 
                                         pegs in the solution)
Applied to the Mastermind board game, snarks could thereby prove that a clue about a secret combination of colours is correct, without revealing the secret itself.

## Implementation
In the implementation the hidden solution is an a array of 4 non-zero digits i.e ["1","2","3","4"] (say).

To reset the private solution run :
> sh scripts/set_soln.sh 

To play the game :
> sh scripts/play.sh 

   It takes about 3-4 minutes to generate the proof which includes compilation of zok file,witness computation, proof generation and verifier contract generation.
## Improvements

* Reduction in proof generation time.
* Frontend to facilitate the game play.
 
## Requirements
*  Hardhat
*  Zokrates

## Resources

* https://weijiek.medium.com/how-i-learned-zk-snarks-from-scratch-177a01c5514e
* https://zokrates.github.io/introduction.html
