pytest-vnc: cross-platform keyboard, video and mouse for pytest
===============================================================

.. image:: https://img.shields.io/badge/source-github-orange
    :target: https://github.com/barneygale/pytest-vnc

.. image:: https://readthedocs.org/projects/pytest-vnc/badge/?version=latest&style=flat-square
    :target: https://pytest-vnc.readthedocs.io/en/latest/?badge=latest

.. image:: https://img.shields.io/pypi/v/pytest-vnc?style=flat-square
    :target: https://pypi.org/project/pytest-vnc


pytest-vnc is a pytest plugin that sends mouse and keyboard input and captures the screen using the VNC protocol. It is
implemented in pure python and works on Mac, Linux and Windows. Use it like this::

    def test_thing(vnc):
        # Keyboard input
        vnc.write('hi there!')  # keys are queued
        vnc.press('Ctrl', 'c')  # keys are stacked
        with client.keyboard.hold('Ctrl'):
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

        # Screenshot
        pixels = vnc.capture()
        pixels = vnc.capture(x=0, y=0, width=vnc.width, height=vnc.height)
        # to use PIL/pillow:
        # image = Image.fromarray(pixels)


Installation
------------

This package requires Python 3.7+.

Install pytest-vnc by running::

    pip install pytest-vnc


Configuration
-------------

The following configuration options can be set in :file:`pytest.ini`:

``vnc_host``
  VNC hostname (default: localhost)
``vnc_port``
  VNC port (default: 5900)
``vnc_speed``
  VNC interactions per second (default: 20)
``vnc_timeout``
  VNC connection timeout in seconds (default: 5)
``vnc_user``
  VNC username (default: :env:`PYTEST_VNC_USER` or current user)
``vnc_passwd``
  VNC password (default: :env:`PYTEST_VNC_PASSWD`)

The following environment variables can be set:

.. envvar:: PYTEST_VNC_USER

    The VNC username to use.

.. envvar:: PYTEST_VNC_PASSWD

    The VNC password to use.
