using Fuse.Scripting;
using Uno;
using Uno.Collections;
using Uno.UX;
using Uno.Net.Sockets;
using Uno.Text;
using Uno.Threading;

[UXGlobalModule]
public class NebulaSocket : NativeEventEmitterModule {
    static readonly NebulaSocket instance;
    bool socketAvailable = false;
    Socket socket;

    public NebulaSocket() : base(true, "onReceive", "onConnect", "onDisconnect", "onError") {
        if (instance != null) { return; }
        
        instance = this;
        Resource.SetGlobalKey(instance, "NebulaSocket");

        AddMember(new NativeFunction("connect", (NativeCallback) Connect));
        AddMember(new NativeFunction("disconnect", (NativeCallback) Disconnect));
        AddMember(new NativeFunction("send", (NativeCallback) Send));
    }

    string Connect(Context c, object[] args) {
        socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socketAvailable = true;

        var address = args[0] as string;
        var port = int.Parse(args[1] as string);
        
        try {
            socket.Connect(address, port);

            Emit("onConnect");
            
            var socketRead = new Thread(Read);
            socketRead.Start();
        } catch(SocketException e) {
            Emit("onError", "Connect = " + e.Message.ToString());
        }

        return "";
    }

    string Disconnect(Context c, object[] args) {
        socketAvailable = false;

        socket.Dispose();
        
        Emit("onDisconnect");

        return "";
    }

    string Send(Context c, object[] args) {
        var message = args[0] as Fuse.Scripting.Array;
        
        try {
            socket.Send(this.ArrayToBytes(message));
        } catch(SocketException e) {
            Emit("onError", "Send = " + e.Message.ToString());
        }

        return "";
    }

    void Read() {
        try {
            while (socketAvailable) {
                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = socket.Receive(buffer)) > 0) {
                    byte[] data = new byte[bytesRead];
                    Uno.Array.Copy(buffer, 0, data, 0, bytesRead);

                    Emit("onReceive", data);
                }
            }
        } catch(SocketException e) {
            // Emit("onError", "Read = " + e.Message.ToString());
        }
    }

    byte[] ArrayToBytes(Fuse.Scripting.Array fsArray) {
        byte[] byteArray = new byte[fsArray.Length];

        for (var i = 0; i < fsArray.Length; i++) {
            byteArray[i] = Uno.Byte.Parse(fsArray[i].ToString());
        }

        return byteArray;
    }
}