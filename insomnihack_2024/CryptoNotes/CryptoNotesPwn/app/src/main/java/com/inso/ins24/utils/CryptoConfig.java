package com.inso.ins24.utils;

/** Clone CryptoConfig class from CryptoNotes App. */
public class CryptoConfig {
  public byte[] ALGO;
  public String IN;

  // public static native String docipher(byte[] arg0, String arg1);

  @Override
  protected void finalize() throws Throwable {
    super.finalize();
    // CryptoConfig.docipher(this.ALGO, this.IN);
  }
}
