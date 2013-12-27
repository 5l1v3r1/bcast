if (process.argv.length != 4) {
    console.log('Usage: node main.js <interface> <file>');
    process.exit();
}

var theInterface = process.argv[2];
var theFile = process.argv[3];

var beaconcoder = require('./beacon.js');
var pcap = require('pcap');
var exec = require('child_process').exec;
var fs = require('fs');


function initialize() {
    var session = pcap.createSession(theInterface, '', 100000, true);
    var command = require('os').platform() == 'darwin' ? 
                      'sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -c11' :
                      'iwconfig ' + theInterface + ' channel 11';
    exec(command, function() {
        fs.readFile(theFile, function(err, data) {
            var lines = data.toString().split('\n');
            console.log('theFile ' + theFile);
            sendNextPacket(session, lines);
        });
    });
}

function sendNextPacket(session, names) {
    var macAddr = new Buffer('\x2E\xB0\x5D\x27\x56\xA9', 'binary');
    
    var beacons = [];
    names.forEach(function(n) {
        var beacon = beaconcoder.encode(n, macAddr);
        beacons.push(beacon);
    });
    
    beacons.forEach(function(b) {
        session.inject(b);
    });
    
    setTimeout(sendNextPacket.bind(null, session, names), 100);
}

initialize();
