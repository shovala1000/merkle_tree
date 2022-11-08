# merkle_tree
## Information
* It is a binary tree.
* The leaves are hash on given information.
* I used SHA256 (hash function).
## Supports
* Supports adding a leaf to the tree (input 1): 
  1. input: a string
  2. no output.
* Supports calculating the current tree (input 2): 
  1. no input
  2. output: tree's root in hexadecimal.
* Supports creating "Proof of inclusion" to a leaf (input 3):
  1. input: leaf's number (0 for the leftmost)
  2. output: "Proof of inclusion".
* Supports checking if "Proof of inclusion" is valid (input 4): 
  1. input: string (leaf's information) and the output of input 3
  2. output: true if valid and false otherwise.
* Supports creating a public key and private key by RSA algorithm (input 5): 
  1. no input
  2. output: the private key and public key.
* Supports creating a signature for the root (input 6):
  1. input: signature's key
  2. output: signature.
* Supports checking if signature is valid (input 7): 
  1. input: key, signature, string
  2. output: true if valid and false otherwise.
