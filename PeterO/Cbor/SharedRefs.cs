/*
Written by Peter O. in 2014.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
using System;
using System.Collections.Generic;
using PeterO;
using PeterO.Numbers;

namespace PeterO.Cbor {
  internal class SharedRefs {
    private readonly IList<CBORObject> sharedObjects;

    public SharedRefs() {
      this.sharedObjects = new List<CBORObject>();
    }

    public void AddObject(CBORObject obj) {
      this.sharedObjects.Add(obj);
    }

    public CBORObject GetObject(long smallIndex) {
      if (smallIndex < 0) {
        throw new CBORException("Unexpected index");
      }
      if (smallIndex > Int32.MaxValue) {
        throw new CBORException("Index " + smallIndex +
                    " is bigger than supported ");
      }
      var index = (int)smallIndex;
      if (index >= this.sharedObjects.Count) {
        throw new CBORException("Index " + index + " is not valid");
      }
      return this.sharedObjects[index];
    }

    public CBORObject GetObject(EInteger bigIndex) {
      if (bigIndex.Sign < 0) {
        throw new CBORException("Unexpected index");
      }
      if (!bigIndex.CanFitInInt32()) {
        throw new CBORException("Index " + bigIndex +
                    " is bigger than supported ");
      }
      var index = (int)bigIndex;
      if (index >= this.sharedObjects.Count) {
        throw new CBORException("Index " + index + " is not valid");
      }
      return this.sharedObjects[index];
    }
  }
}
