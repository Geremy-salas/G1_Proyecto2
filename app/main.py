import logging
import os

from flask import Flask, render_template, request
import google.cloud.logging
from google.cloud import firestore
from google.cloud import storage
from google.cloud import vision

client = google.cloud.logging.Client()
client.get_default_handler()
client.setup_logging()

app = Flask(__name__)

# Instancia de Vision para reutilizar
vision_client = vision.ImageAnnotatorClient()

@app.route('/')
def root():
    return render_template('home.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    successful_upload = False
    objects_detected = []
    extracted_text = ""
    phishing_result = "No evaluado"

    if request.method == 'POST':
        uploaded_file = request.files.get('picture')

        if uploaded_file:
            gcs = storage.Client()
            bucket = gcs.get_bucket(os.environ.get('BUCKET', 'my-bmd-bucket'))
            blob = bucket.blob(uploaded_file.filename)

            # Subir la imagen al bucket
            blob.upload_from_string(
                uploaded_file.read(),
                content_type=uploaded_file.content_type
            )

            logging.info(blob.public_url)

            # Análisis de la imagen
            objects_detected = detect_objects(blob.public_url)
            extracted_text = extract_text(blob.public_url)
            phishing_result = detect_phishing(extracted_text)

            successful_upload = True

    return render_template(
        'upload_photo.html',
        successful_upload=successful_upload,
        objects_detected=objects_detected,
        extracted_text=extracted_text,
        phishing_result=phishing_result
    )


class TypeError:
    pass


@app.route('/search')
def search():
    query = request.args.get('q')
    results = []

    if query:
        db = firestore.Client()
        doc = db.collection(u'tags').document(query.lower()).get().to_dict()

        try:
            for url in doc['photo_urls']:
                results.append(url)
        except TypeError:
            pass

    return render_template('search.html', query=query, results=results)


@app.errorhandler(500)
def server_error(e):
    logging.exception('An error occurred during a request.')
    return render_template('error.html'), 500


def detect_objects(image_uri):
    """Detecta objetos en la imagen."""
    image = vision.Image(source=vision.ImageSource(image_uri=image_uri))
    objects = vision_client.object_localization(image=image).localized_object_annotations
    return [obj.name for obj in objects]


def extract_text(image_uri):
    """Extrae texto de la imagen."""
    image = vision.Image(source=vision.ImageSource(image_uri=image_uri))
    response = vision_client.text_detection(image=image)
    texts = response.text_annotations
    return texts[0].description if texts else ""


def detect_phishing(extracted_text):
    """Determina si el texto podría ser phishing."""
    phishing_keywords = ["password", "login", "verification", "bank", "account", "urgent"]
    for word in phishing_keywords:
        if word.lower() in extracted_text.lower():
            return "Posible phishing detectado"
    return "No es phishing"


def int(param):
    pass


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
