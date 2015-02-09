$(document).ready(function() {
    if (!window.console) window.console = {};
    if (!window.console.log) window.console.log = function() {};

    updater.start();
});


var updater = {
    socket: null,

    start: function() {
        var url = "ws://" + location.host + "/socket/trebol/";
        updater.socket = new WebSocket(url);
        updater.socket.onmessage = function(event) {
            updater.updateStatus(JSON.parse(event.data));
        };
    },

    updateStatus: function(msg) {
        var row = $("tr[data-device=" + msg.device + "] td");
        $(row[1]).html('<p>' + msg.address + '</p>');

        if (msg.action === "connect") {
            $(row[2]).html('<p class="text-success">Connected.</p>');
        }
        else if (msg.action === "disconnect") {
            $(row[2]).html('<p class="text-danger">Not connected.</p>');
        }
    }
};
