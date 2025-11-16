// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileVaultWithIPFS {
    struct FileRecord {
        string filename;
        string fileHash;
        address owner;
        uint256 timestamp;
        string encAesKeyB64;  // RSA-encrypted AES key
        string ipfsCid;       // CID (encrypted file stored on IPFS)
    }

    mapping(string => FileRecord) public records;

    event FileStored(
        string indexed fileHash,
        string filename,
        string ipfsCid,
        address indexed owner,
        uint256 timestamp
    );

    function storeFileWithKeyAndCID(
        string memory _filename,
        string memory _fileHash,
        string memory _encAesKeyB64,
        string memory _ipfsCid
    ) public {
        require(bytes(records[_fileHash].fileHash).length == 0, "File already exists!");

        records[_fileHash] = FileRecord(
            _filename,
            _fileHash,
            msg.sender,
            block.timestamp,
            _encAesKeyB64,
            _ipfsCid
        );

        emit FileStored(_fileHash, _filename, _ipfsCid, msg.sender, block.timestamp);
    }

    function getFileWithKeyAndCID(string memory _fileHash)
        public
        view
        returns (
            string memory,
            string memory,
            address,
            uint256,
            string memory,
            string memory
        )
    {
        FileRecord memory rec = records[_fileHash];
        return (
            rec.filename,
            rec.fileHash,
            rec.owner,
            rec.timestamp,
            rec.encAesKeyB64,
            rec.ipfsCid
        );
    }
}


