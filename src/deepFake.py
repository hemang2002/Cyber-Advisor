# type: ignore
from transformers import pipeline
import torch
import os
import json
import warnings
from dotenv import load_dotenv
import ast

load_dotenv()

warnings.filterwarnings("ignore")

def deepfake_analysis(image_path):
    """
    Perform deepfake analysis on the given image using a pre-trained model.
    """
    try:
        device = 0 if torch.cuda.is_available() else -1
        pipe = pipeline(
            'image-classification', 
            model = os.getenv("MODEL_NAME"), 
            device = device)

        result = pipe(image_path)
        result = [
            {"Label": result[1]['label'], "Score": result[0]['score']},
            {"Label": result[0]['label'], "Score": result[1]['score']}
        ]
        return result[0]
    except Exception as e:
        return {"error": str(e)}