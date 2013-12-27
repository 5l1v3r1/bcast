var crc = require('./crc.js');
var pcap = require('pcap');
var session = pcap.createSession('en0', '', 65536, true);
var child = require('child_process');

function encodeBeaconFrame(name, mac) {
    var header = new Buffer('\x80\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF', 'binary');
    var postHeader = new Buffer('\x20\x77\xBB\x6A\x04\xD3\xE0\x00\x00\x00\xC8\x00\x11\x00\x00', 'binary');
    var suffix = new Buffer('\x01\x08\x82\x84\x8B\x96\x24\x30\x48\x6C\x03\x01\x0B\x05\x04\x00\x02\x00\x00\x2A\x01\x00\x2F\x01\x00\x30\x14\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x02\x00\x00\x32\x04\x0C\x12\x18\x60\x2D\x1A\xFC\x18\x1B\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3D\x16\x0B\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xDD\x09\x00\x10\x18\x02\x00\xF0\x28\x00\x00', 'binary');
    // header + mac + mac + postHeader + len-byte + name + suffix
    var body =  Buffer.concat([header, mac, mac, postHeader, new Buffer([name.length]), 
                              new Buffer(name), suffix]);
    // calculate checksum
    var sum = crc.crc32(body);
    var cSumBuffer = new Buffer([~(sum >> 0) & 0xff, ~(sum >> 8) & 0xff, 
                                 ~(sum >> 16) & 0xff, ~(sum >> 24) & 0xff]);
    body = Buffer.concat([new Buffer('\x00\x00\x08\x00\x00\x00\x00\x00', 'binary'), body, cSumBuffer]);
    return body;
}

session.on('packet', function(p) {
    console.log('got packet');
});

function sendNextPacket() {
    // broadcast nonesense beacons
    var cmds = 'sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -c';
    var macAddr = new Buffer('\x2E\xB0\x5D\x27\x56\xA9', 'binary');
    
    var names = ['Network', 'Network1', 'Network2'];
    var beacons = [];
    names.forEach(function(n) {
        var beacon = encodeBeaconFrame(n, macAddr);
        beacons.push(beacon);
    });
    child.exec(cmds + '10', function(err, stdout) {
        beacons.forEach(function(b) { session.inject(b); });
        child.exec(cmds + '11', function(err, stdout) {
            beacons.forEach(function(b) { session.inject(b); });
            child.exec(cmds + '12', function(err, stdout) {
                beacons.forEach(function(b) { session.inject(b); });
                setTimeout(sendNextPacket, 100);
            });
        });
    });
}

sendNextPacket();
