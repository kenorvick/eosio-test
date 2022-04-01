import React, { useEffect } from "react";
import { StyleSheet } from "react-native";
import QRCodeScanner from "react-native-qrcode-scanner";
import Client from "./utils/Client";

export default function App() {
  useEffect(() => {
    (async () => {
      await Client.initialize();
    })();
  }, []);

  const onSuccess = (e) => {
    Client.handleIdentityRequest(e.data);
  };

  return <QRCodeScanner onRead={onSuccess} />;
}

const styles = StyleSheet.create({
  centerText: {
    flex: 1,
    fontSize: 18,
    padding: 32,
    color: "#777",
  },
  textBold: {
    fontWeight: "500",
    color: "#000",
  },
  buttonText: {
    fontSize: 21,
    color: "rgb(0,122,255)",
  },
  buttonTouchable: {
    padding: 16,
  },
});
