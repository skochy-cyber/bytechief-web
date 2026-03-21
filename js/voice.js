/**
 * ByteChief AI — Voice Manager
 * Web Speech API — speech recognition + synthesis
 */
class VoiceManager {
  constructor(callbacks = {}) {
    this.onResult  = callbacks.onResult  || (() => {});
    this.onStart   = callbacks.onStart   || (() => {});
    this.onEnd     = callbacks.onEnd     || (() => {});
    this.onError   = callbacks.onError   || (() => {});
    this.isActive  = false;
    this.recognition = null;
    this.synthesis   = window.speechSynthesis || null;
    this._init();
  }

  _init() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) { console.warn('Speech recognition not supported'); return; }
    this.recognition = new SR();
    this.recognition.continuous    = false;
    this.recognition.interimResults = true;
    this.recognition.lang           = 'en-US';

    this.recognition.onstart = () => { this.isActive = true; this.onStart(); };
    this.recognition.onend   = () => { this.isActive = false; this.onEnd(); };
    this.recognition.onerror = (e) => { this.isActive = false; this.onEnd(); this.onError(e.error); };

    this.recognition.onresult = (e) => {
      let transcript = '';
      for (let i = e.resultIndex; i < e.results.length; i++) {
        transcript += e.results[i][0].transcript;
      }
      if (e.results[e.results.length - 1].isFinal) {
        this.onResult(transcript.trim());
      }
    };
  }

  toggle() {
    if (!this.recognition) {
      // FIX: dispatch event instead of alert() so UI can handle it gracefully
      window.dispatchEvent(new CustomEvent('voiceUnsupported'));
      return;
    }
    if (this.isActive) {
      this.recognition.stop();
    } else {
      try { this.recognition.start(); } catch (e) { console.warn('Recognition start error:', e); }
    }
  }

  start() { if (this.recognition && !this.isActive) this.recognition.start(); }
  stop()  { if (this.recognition && this.isActive)  this.recognition.stop(); }

  speak(text, opts = {}) {
    if (!this.synthesis) return;
    this.synthesis.cancel();
    const utt = new SpeechSynthesisUtterance(text);
    utt.rate   = opts.rate   || 1;
    utt.pitch  = opts.pitch  || 1;
    utt.volume = opts.volume || 1;
    utt.lang   = opts.lang   || 'en-US';
    this.synthesis.speak(utt);
  }
}
