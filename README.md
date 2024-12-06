# ByteTide - P2P File Transfer

ByteTide is a Peer-to-Peer (P2P) file transfer program designed to manage the sending, receiving, and integrity checking of file chunks. It allows peers to communicate directly with one another to exchange data, detect anomalous chunks, and ensure file integrity, without the need for centralized servers. This program uses a specialized file format and a Merkle tree structure for efficient data verification.

# Features
- Package Loading: Parses .bpkg files, which describe the file structure and chunks, to manage file data efficiently.
- Merkle Tree Construction: Builds and computes a Merkle tree to verify file integrity by hashing chunks and comparing computed and expected hashes.
- File Integrity Check: Ensures that each chunk of data matches the expected hash value, identifying anomalies.
- Chunk Management: Handles incomplete and completed chunks, ensuring proper file assembly and integrity.