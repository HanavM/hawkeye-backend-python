import cv2
import requests
import os

# Azure OCR Subscription Key and Endpoint (make sure to replace these with your actual values)
subscription_key = "55f1a99e6cce406eb37567a7e6cf1d13"
ocr_endpoint = "https://hawkeye-cv-test2-hanavmodasiya.cognitiveservices.azure.com/vision/v3.2/ocr"

# Frame extraction directory
frame_output_dir = "test_frames"

def extract_text_from_image(image_data):
    try:
        headers = {
            'Ocp-Apim-Subscription-Key': subscription_key,
            'Content-Type': 'application/octet-stream'
        }
        params = {'language': 'en', 'detectOrientation': 'true'}
        response = requests.post(ocr_endpoint, headers=headers, params=params, data=image_data)

        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            return None

        ocr_result = response.json()
        extracted_text = []
        for region in ocr_result.get('regions', []):
            for line in region['lines']:
                line_text = ' '.join([word['text'] for word in line['words']])
                extracted_text.append(line_text)

        return " ".join(extracted_text)

    except Exception as e:
        print(f"Error extracting text from image: {str(e)}")
        return None

def process_video(video_path, frame_interval=120):
    try:
        if not os.path.exists(frame_output_dir):
            os.makedirs(frame_output_dir)

        video_capture = cv2.VideoCapture(video_path)
        frame_count = 0
        success = True
        extracted_texts = []

        while success:
            success, frame = video_capture.read()

            if success and frame_count % frame_interval == 0:
                frame_filename = f"{frame_output_dir}/frame_{frame_count}.jpg"
                cv2.imwrite(frame_filename, frame)

                with open(frame_filename, "rb") as frame_file:
                    image_data = frame_file.read()

                text = extract_text_from_image(image_data)
                if text:
                    extracted_texts.append({"frame": frame_count, "text": text})

            frame_count += 1

        video_capture.release()

        return extracted_texts

    except Exception as e:
        print(f"Error processing video: {str(e)}")
        return None

if __name__ == "__main__":
    # Test the video processing function

    # Specify the path to the test video file
    video_path = "/Users/hanavmodasiya/Downloads/video.mp4"

    # Process the video and extract text from frames
    extracted_texts = process_video(video_path, frame_interval=120)

    # Print the extracted text
    if extracted_texts:
        print("Extracted text from video frames:")
        for item in extracted_texts:
            print(f"Frame {item['frame']}: {item['text']}")
    else:
        print("No text extracted from the video frames.")
