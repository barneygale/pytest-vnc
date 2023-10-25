pytest-vnc: capture screen and send keyboard & mouse
====================================================

.. image:: https://img.shields.io/badge/source-github-orange
    :target: https://github.com/barneygale/pytest-vnc

.. image:: https://img.shields.io/pypi/v/pytest-vnc?style=flat-square
    :target: https://pypi.org/project/pytest-vnc


pytest-vnc implements a VNC client in pure Python. It works on Mac, Linux and Windows. Use the ``vnc`` fixture to
capture screenshots and send keyboard & mouse from your pytest tests:

.. code-block:: python

    def test_thing(vnc):
        # Screenshot
        print(vnc.width, vnc.height)
        pixels = vnc.capture()  # rgba numpy array of entire screen
        pixels = vnc.capture(x=100, y=0, width=50, height=75)
        # to use PIL/pillow:
        # image = Image.fromarray(pixels)

        # Keyboard input
        vnc.write('hi there!')  # keys are queued
        vnc.press('Ctrl', 'c')  # keys are stacked
        with vnc.hold('Ctrl'):
            vnc.press('Esc')

        # Mouse input
        vnc.move(100, 200)
        vnc.click()
        vnc.double_click()
        vnc.middle_click()
        vnc.right_click()
        vnc.scroll_up()
        vnc.scroll_down(repeat=10)
        with vnc.drag():
            vnc.move(300, 400)
        with vnc.middle_drag():
            vnc.move(500, 600)
        with vnc.right_drag():
            vnc.move(700, 800)


Installation
------------

This package requires Python 3.7+.

Install pytest-vnc by running::

    pip install pytest-vnc


Configuration
-------------

The following configuration options can be set in ``pytest.ini``:

``vnc_host``
  VNC hostname (default: localhost)
``vnc_port``
  VNC port (default: 5900)
``vnc_speed``
  VNC interactions per second (default: 20)
``vnc_timeout``
  VNC connection timeout in seconds (default: 5)
``vnc_pixel_format``
  VNC colour channel order (default: rgba)
``vnc_user``
  VNC username (default: env var: ``PYTEST_VNC_USER`` or current user)
``vnc_passwd``
  VNC password (default: env var: ``PYTEST_VNC_PASSWD``)

The following attributes can be set on the ``vnc`` object:

``speed``
  Interactions per second (default: 20)
``sleep``
  Callable that accepts a duration in seconds and waits for that long (default: ``time.sleep()``)
