# type: ignore

import asyncio
import io
import os
import platform
from groq import Groq
import pygame
import pyaudio
import wave

#############################text to speech################################################
def text_to_speech_play(text):
    try:
        pygame.mixer.init()
        response = client.audio.speech.create(
            model="playai-tts",
            input=text,
            voice="Arista-PlayAI",
            # voice="Atlas-PlayAI"
            response_format="wav"
        )
        audio_data = io.BytesIO(response.read())
        pygame.mixer.music.load(audio_data)
        pygame.mixer.music.play()
        while pygame.mixer.music.get_busy():
            asyncio.sleep(0.1)

        pygame.mixer.music.stop()
        pygame.mixer.quit()

        print("Audio playback completed.")

    except Exception as e:
        print(f"Error during text-to-speech playback: {str(e)}")

async def main_text():
    sample_text = input("Enter text here:")
    await text_to_speech_play(sample_text)

#############################Speech to text################################################
def record_and_transcribe():
    """
    Record live audio from the microphone and transcribe it using Groq's whisper-large-v3,
    without saving files.
    """
    try:
        audio = pyaudio.PyAudio()

        print("Recording... Speak now! (Ctrl+C to stop)")

        while True:
            stream = audio.open(
                format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                frames_per_buffer=CHUNK
            )

            frames = []
            for _ in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
                data = stream.read(CHUNK)
                frames.append(data)

            stream.stop_stream()
            stream.close()

            audio_buffer = io.BytesIO()
            with wave.open(audio_buffer, 'wb') as wf:
                wf.setnchannels(CHANNELS)
                wf.setsampwidth(audio.get_sample_size(FORMAT))
                wf.setframerate(RATE)
                wf.writeframes(b''.join(frames))

            audio_buffer.seek(0)

            transcription = client.audio.transcriptions.create(
                file=("temp.wav", audio_buffer.read()),
                model="whisper-large-v3",
                response_format="verbose_json"
            )

            print("Transcription:", transcription.text)

    except KeyboardInterrupt:
        print("Stopped recording.")
    except Exception as e:
        print(f"Error during recording or transcription: {str(e)}")
    finally:
        audio.terminate()

def main_audio():
    record_and_transcribe()


if __name__=="__main__":
    
    input_ = input("Write \"s\" T2S or \"t\" S2T:")
    client = Groq(api_key=os.getenv("GROK_API_KEY")) 

    if input_.lower()=="s":
        if platform.system() == "Emscripten":
            asyncio.ensure_future(main_text())
        else:
            asyncio.run(main_text())
    else:
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 16000
        RECORD_SECONDS = 2
        if platform.system() == "Emscripten":
            main_audio()
        else:
            main_audio()