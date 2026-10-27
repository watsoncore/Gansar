"""Bundled report resources; originals and current presentation remain intact."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from PIL import Image
from app.exporters import html_exporter as exporter

ROOT=Path(__file__).resolve().parents[1]
BACKGROUND=ROOT/'app/exporters/assets/report-backgrounds/lesli.png'
LOGO=ROOT/'app/exporters/assets/report-logos/logo.mp4'
GIF=ROOT/'htmlG/assets/Emma Watson Kiss GIF.gif'

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

class ReportMediaResources(unittest.TestCase):
    @contextmanager
    def installed_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);fake=base/'install/app/exporters/html_exporter.py'
            for source,kind in ((BACKGROUND,'report-backgrounds'),(LOGO,'report-logos')):
                target=fake.parent/'assets'/kind/source.name
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
            cwd=base/'unrelated';cwd.mkdir();output=base/'new-report';output.mkdir()
            with patch.object(exporter,'__file__',str(fake)),patch.object(Path,'cwd',return_value=cwd):
                yield fake.parents[2],output

    def test_bundled_files_are_exact_original_output_resources(self):
        self.assertEqual(digest(BACKGROUND),'9e61b53c0f43f3cb9b419b7f4293070ff1f5a90b25148d7cf3f0fa9436eec013')
        self.assertEqual(digest(LOGO),'2987ae8eea1f01da64f92dc3de24c2ec2ab5a6a9b375e5d2359fa22c9f63f282')
        with Image.open(BACKGROUND) as image:
            self.assertEqual(image.format,'PNG');self.assertEqual(image.size,(1672,941))
        self.assertEqual(LOGO.read_bytes()[4:8],b'ftyp')

    def test_no_local_branding_uses_packaged_defaults_and_portable_urls(self):
        with self.installed_layout() as (_,output):
            background=exporter._background_config(output);logo=exporter._logo_config(output)
            self.assertEqual(background['image'],'fon/lesli.png')
            self.assertEqual(background['video'],'')
            self.assertEqual(logo,{'image':'','video':'logo/logo.mp4'})
            self.assertEqual(digest(output/background['image']),digest(BACKGROUND))
            self.assertEqual(digest(output/logo['video']),digest(LOGO))

    def test_report_local_animation_precedes_bundled_default_without_reencoding(self):
        with self.installed_layout() as (_,output):
            for kind in ('fon','logo'):
                target=output/kind/'custom.gif';target.parent.mkdir();shutil.copy2(GIF,target)
            self.assertEqual(exporter._fon_media(output),{'url':'fon/custom.gif','type':'image'})
            self.assertEqual(exporter._logo_media(output),{'url':'logo/custom.gif','type':'image'})
            for kind in ('fon','logo'):
                copied=output/kind/'custom.gif';self.assertEqual(digest(copied),digest(GIF))
                with Image.open(copied) as image:self.assertGreater(image.n_frames,1)

    def test_existing_root_customization_still_precedes_output_and_package(self):
        with self.installed_layout() as (project,output):
            (project/'fon').mkdir();(project/'logo').mkdir()
            shutil.copy2(BACKGROUND,project/'fon/own.png')
            shutil.copy2(LOGO,project/'logo/own.mp4')
            (output/'fon').mkdir();shutil.copy2(GIF,output/'fon/custom.gif')
            self.assertEqual(exporter._fon_media(output)['url'],'fon/own.png')
            self.assertEqual(exporter._logo_media(output)['url'],'logo/own.mp4')
            self.assertEqual(digest(output/'fon/own.png'),digest(BACKGROUND))
            self.assertEqual(digest(output/'logo/own.mp4'),digest(LOGO))

if __name__=='__main__':unittest.main()
