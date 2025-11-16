// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileVaultWithKey {
    struct FileRecord {
        string filename;
        string fileHash;
        address owner;
        uint256 timestamp;
        string encAesKeyB64; // base64-encoded RSA-encrypted AES key
    }

    // Map fileHash => record
    mapping(string => FileRecord) public records;

    event FileStored(
        string indexed fileHash,
        string filename,
        address indexed owner,
        uint256 timestamp
    );

    /**
     * Store filename, fileHash and the RSA-encrypted AES key (base64 string).
     * Reverts if the fileHash already exists.
     */
    function storeFileWithKey(
        string memory _filename,
        string memory _fileHash,
        string memory _encAesKeyB64
    ) public {
        require(bytes(records[_fileHash].fileHash).length == 0, "File already exists!");

        records[_fileHash] = FileRecord({
            filename: _filename,
            fileHash: _fileHash,
            owner: msg.sender,
            timestamp: block.timestamp,
            encAesKeyB64: _encAesKeyB64
        });

        emit FileStored(_fileHash, _filename, msg.sender, block.timestamp);
    }

    /**
     * Existing getter (returns same data as before, plus encAesKey)
     */
    function getFileWithKey(string memory _fileHash)
        public
        view
        returns (
            string memory filename,
            string memory fileHash,
            address owner,
            uint256 timestamp,
            string memory encAesKeyB64
        )
    {
        FileRecord memory rec = records[_fileHash];
        return (rec.filename, rec.fileHash, rec.owner, rec.timestamp, rec.encAesKeyB64);
    }
}
