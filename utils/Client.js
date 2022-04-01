import { Listener, ListenerEncoding } from "@greymass/buoy";
import { PrivateKey, Serializer, Struct } from "@greymass/eosio";
import axios from "axios";
import { Buffer } from "buffer";
import { SigningRequest } from "eosio-signing-request";
import { Api, JsonRpc } from "eosjs";
import { JsSignatureProvider } from "eosjs/dist/eosjs-jssig";
import * as SecureStore from "expo-secure-store";
import { debounce } from "lodash";
import zlib from "react-zlib-js";
import encoding from "text-encoding";

const esrParams = ["bn", "ex", "rbn", "req", "rid", "sa", "sig", "sp", "tx"];
const rpc = new JsonRpc("https://eos.greymass.com");
const textEncoder = new encoding.TextEncoder();
const textDecoder = new encoding.TextDecoder();

global.Buffer = Buffer;

@Struct.type("sealed_message")
export class SealedMessage extends Struct {
  @Struct.field("public_key") from;
  @Struct.field("uint64") nonce;
  @Struct.field("bytes") ciphertext;
  @Struct.field("uint32") checksum;
}

class Client {
  constructor() {
    this.privateKey = "";
    this.publicKey = "";
    this.accountName = "";
    this.eos = null;
    this.listener = null;
  }

  initialize = async () => {
    this.eos = new Api({
      rpc,
      signatureProvider: new JsSignatureProvider([this.privateKey]),
      textDecoder,
      textEncoder,
    });

    const walletSession = await SecureStore.getItemAsync("walletSession");
    if (walletSession) this.restoreSession();
  };

  callbackURIWithProcessed = async (callback) => {
    const { payload, url } = callback;
    let s = url;
    esrParams.forEach((param) => {
      s = s.replace(`{{${param}}}`, payload[param]);
    });
    await axios.post(s, payload);
  };

  resolveUri = async (uri) => {
    const opts = {
      textEncoder,
      textDecoder,
      zlib: {
        deflateRaw: (data) =>
          new Uint8Array(zlib.deflateRawSync(Buffer.from(data))),
        inflateRaw: (data) =>
          new Uint8Array(zlib.inflateRawSync(Buffer.from(data))),
      },
      abiProvider: {
        getAbi: async (account) => await this.eos.getAbi(account),
      },
      scheme: "esr",
    };
    // Decode the URI
    const decoded = SigningRequest.from(uri, opts);
    const req = JSON.parse(JSON.stringify(decoded.data));

    // In order to resolve the transaction, we need a recent block to form it into a signable transaction
    const head = (await rpc.get_info(true)).head_block_num;
    const block = await rpc.get_block(head);

    // Fetch the ABIs needed for decoding
    const abis = await decoded.fetchAbis();

    // An authorization to resolve the transaction to
    const authorization = {
      actor: this.accountName,
      permission: "active",
    };
    const resolved = decoded.resolve(abis, authorization, block);

    // Resolve the transaction as a specific user
    return { resolved, callbackUrl: req.callback, abis };
  };

  signResolvedUri = async ({ resolved, callbackUrl, abis }) => {
    const signed = await this.eos.signatureProvider.sign({
      chainId: resolved.chainId.toString(),
      requiredKeys: [this.publicKey],
      serializedTransaction: resolved.serializedTransaction,
      abis,
    });

    let callbackParams = resolved.getCallback(signed.signatures, 0);

    callbackParams.payload = {
      ...callbackParams.payload,
      req: callbackParams?.payload.req.replace("undefined", "esr"),
      link_ch: callbackUrl,
      link_key: PrivateKey.from(this.privateKey).toPublic().toString(),
      link_name: "mydapp",
    };

    return callbackParams;
  };

  setupListener = (url) => {
    const listenerOptions = {
      autoConnect: true,
      encoding: ListenerEncoding.binary,
      service: `https://cb.anchor.link`,
      channel: String(url.split("link/").pop()),
    };
    const listener = new Listener(listenerOptions);

    listener.on("connect", () => {
      try {
        console.log("connected websocket");
      } catch (e) {
        console.log("SessionManager on:connect exception", e);
      }
    });

    listener.on("disconnect", () => {
      try {
        console.log("disconnect websocket");
      } catch (e) {
        console.log("SessionManager on:disconnect exception", e);
      }
    });

    listener.on("message", (message) => {
      try {
        this.handleRequest(message);
      } catch (e) {
        console.log("SessionManager on:message exception", e);
      }
    });

    listener.on("error", (error) => {
      try {
        console.log("error websocket");
      } catch (e) {
        console.log("SessionManager on:error exception", e);
      }
    });

    return listener;
  };

  restoreSession = async () => {
    const walletSession = await SecureStore.getItemAsync("walletSession");
    if (walletSession) {
      const session = JSON.parse(walletSession);
      setTimeout(async () => {
        try {
          const { callbackUrl } = await this.resolveUri(session.payload);
          this.listener = this.setupListener(callbackUrl);
        } catch (e) {
          return console.log({ e });
        }
      }, 250);
    }
    return;
  };

  handleIdentityRequest = debounce(async (uri) => {
    setTimeout(async () => {
      try {
        const { resolved, callbackUrl, abis } = await this.resolveUri(uri);
        const callbackParams = await this.signResolvedUri({
          resolved,
          callbackUrl,
          abis,
        });

        const session = {
          network: resolved.chainId.toString(),
          actor: callbackParams.payload.sa,
          permission: callbackParams.payload.sp,
          payload: resolved.request.toString(),
        };

        await this.callbackURIWithProcessed(callbackParams);
        await SecureStore.setItemAsync(
          "walletSession",
          JSON.stringify(session)
        );
      } catch (e) {
        return console.log({ e });
      }
    }, 250);

    return;
  }, 1000);

  handleRequest(encoded) {
    try {
      const message = Serializer.decode({
        type: SealedMessage,
        data: encoded,
      });
      console.log({ message });
    } catch (e) {
      return e.message;
    }
  }
}

export default new Client();
