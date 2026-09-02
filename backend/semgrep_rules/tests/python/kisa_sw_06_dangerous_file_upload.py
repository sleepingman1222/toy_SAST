def unsafe(upload):
    # ruleid: kisa.sw06.python.unvalidated-upload-filename
    upload.save(upload.filename)

def safe(upload, generated_path):
    # ok: kisa.sw06.python.unvalidated-upload-filename
    upload.save(generated_path)
