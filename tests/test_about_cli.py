from pathlib import Path
import unittest
from unittest.mock import patch
import app.main as cli

class AboutCliTests(unittest.TestCase):
 def test_preserves_six_commands_and_adds_only_seven(self):
  for lang in ['ru','en']:
   rows=cli.UI[lang]['menu'];self.assertEqual([r[0]for r in rows],['1','2','3','4','5','6','7']);self.assertEqual(rows[-1][1],'О проекте'if lang=='ru'else'About')
 def test_opens_exact_local_file_without_changing_cwd(self):
  with patch.object(cli.webbrowser,'open',return_value=True)as browser,patch.object(cli.console,'print'):
   self.assertTrue(cli.open_about_page());browser.assert_called_once_with((Path(cli.__file__).resolve().parent.parent/'htmlG/about.html').as_uri(),new=2)
 def test_missing_file_keeps_cli_available_and_reports_path(self):
  with patch.object(Path,'is_file',return_value=False),patch.object(cli.webbrowser,'open')as browser,patch.object(cli,'error_panel')as error:
   self.assertFalse(cli.open_about_page());browser.assert_not_called();self.assertIn('htmlG',error.call_args.args[1])
 def test_browser_false_is_honest_error(self):
  with patch.object(cli.webbrowser,'open',return_value=False),patch.object(cli,'error_panel')as error:
   self.assertFalse(cli.open_about_page());self.assertIn('about.html',error.call_args.args[1])
 def test_browser_exception_is_local_error(self):
  with patch.object(cli.webbrowser,'open',side_effect=OSError('controlled browser failure')),patch.object(cli,'error_panel')as error:
   self.assertFalse(cli.open_about_page());self.assertIn('controlled browser failure',error.call_args.args[1])
 def test_menu_returns_to_loop_after_about(self):
  with patch.object(cli,'startup_screen'),patch.object(cli,'main_menu',side_effect=['7','6'])as menu,patch.object(cli,'open_about_page',return_value=False)as about,patch.object(cli.console,'print'):
   cli.run();self.assertEqual(menu.call_count,2);about.assert_called_once()

if __name__=='__main__':unittest.main()
