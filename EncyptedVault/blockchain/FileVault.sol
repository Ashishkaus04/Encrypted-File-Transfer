// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileVault {
    struct FileRecord {
        string filename;
        string fileHash;
        address owner;
        uint256 timestamp;
    }

    mapping(string => FileRecord) public records;  // map hash => record

    event FileStored(string fileHash, string filename, address owner, uint256 timestamp);

    function storeFile(string memory _filename, string memory _fileHash) public {
        require(bytes(records[_fileHash].fileHash).length == 0, "File already exists!");

        records[_fileHash] = FileRecord({
            filename: _filename,
            fileHash: _fileHash,
            owner: msg.sender,
            timestamp: block.timestamp
        });

        emit FileStored(_fileHash, _filename, msg.sender, block.timestamp);
    }

    function getFile(string memory _fileHash)
        public
        view
        returns (string memory, string memory, address, uint256)
    {
        FileRecord memory rec = records[_fileHash];
        return (rec.filename, rec.fileHash, rec.owner, rec.timestamp);
    }
}
