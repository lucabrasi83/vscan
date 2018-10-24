<?xml version="1.0" encoding="UTF-8"?>
<!--
  Copyright (C) 2013-2017 JovalCM.com.  All rights reserved.

  This is a very inefficient way to copy XML using XSL, and for the most part it is not
  necessary to ever use this because the Joval sensor supports raw serialization of its
  report formats. However, if you want to perform a one-off scan using XPERT and need
  to inspect a raw XSL source type for some reason, this is the transform to use.
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="/"/>
  </xsl:template>
</xsl:stylesheet> 
