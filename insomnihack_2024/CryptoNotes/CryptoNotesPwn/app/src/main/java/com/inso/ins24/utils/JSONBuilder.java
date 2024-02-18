package com.inso.ins24.utils;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/** Clone JSONBuilder class from CryptoNotes App. */
public class JSONBuilder implements Parcelable {
  public static final Parcelable.Creator CREATOR = new Parcelable.Creator() {
    public JSONBuilder createFromParcel(Parcel parcel) {
      return new JSONBuilder(parcel);
    }
    public JSONBuilder[] newArray(int i) {
      return new JSONBuilder[i];
    }
  };
  private static final Gson JSON = new GsonBuilder().create();
  public Object data;

  private JSONBuilder(Parcel parcel) {
    try {
      Class class0 = Class.forName(parcel.readString());
      String s = parcel.readString();
      this.data = JSONBuilder.JSON.fromJson(s, class0);
      return;
    }
    catch(ClassNotFoundException e) {
      throw new RuntimeException(e);
    }
  }

  // JSONBuilder(Parcel x-1, com.inso.ins24.utils.JSONBuilder.1 x1) {
  //   this(x-1);
  // }

  @Override  // android.os.Parcelable
  public int describeContents() {
    return 0;
  }

  @Override  // android.os.Parcelable
  public void writeToParcel(Parcel parcel, int i) {
    parcel.writeString(this.data.getClass().getCanonicalName());
    parcel.writeString(JSONBuilder.JSON.toJson(this.data));
  }
}
