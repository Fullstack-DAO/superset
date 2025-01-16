/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import React, { forwardRef, useImperativeHandle, useState } from 'react';
import Modal from 'src/components/Modal';
import Button from 'src/components/Button';

interface ModalTriggerProps {
  dialogClassName?: string;
  triggerNode: React.ReactNode;
  modalTitle?: string;
  modalBody?: React.ReactNode;
  modalFooter?: React.ReactNode;
  beforeOpen?: Function;
  onExit?: Function;
  isButton?: boolean;
  className?: string;
  tooltip?: string;
  width?: string;
  maxWidth?: string;
  responsive?: boolean;
  resizable?: boolean;
  resizableConfig?: any;
  draggable?: boolean;
  draggableConfig?: any;
  destroyOnClose?: boolean;
}

export interface ModalTriggerRef {
  current: {
    close: () => void;
    open: (e: React.MouseEvent) => void;
  };
}

const ModalTrigger = forwardRef(
  (props: ModalTriggerProps, ref: ModalTriggerRef) => {
    const [showModal, setShowModal] = useState(false);

    const close = () => {
      setShowModal(false);
      props.onExit?.();
    };

    const open = (e: React.MouseEvent) => {
      e.preventDefault();
      props.beforeOpen?.();
      setShowModal(true);
    };

    useImperativeHandle(ref, () => ({
      close,
      open,
    }));

    return (
      <>
        {props.isButton && (
          <Button
            className="modal-trigger"
            data-test="btn-modal-trigger"
            tooltip={props.tooltip}
            onClick={open}
          >
            {props.triggerNode}
          </Button>
        )}
        {!props.isButton && (
          <span
            data-test="span-modal-trigger"
            onClick={open}
            role="button"
            tabIndex={0}
            onKeyPress={(e: React.KeyboardEvent) => {
              if (e.key === 'Enter') {
                open(e as unknown as React.MouseEvent);
              }
            }}
            style={{ cursor: 'pointer' }}
          >
            {props.triggerNode}
          </span>
        )}
        <Modal
          className={props.className}
          show={showModal}
          onHide={close}
          title={props.modalTitle}
          footer={props.modalFooter}
          hideFooter={!props.modalFooter}
          width={props.width}
          maxWidth={props.maxWidth}
          responsive={props.responsive}
          resizable={props.resizable}
          resizableConfig={props.resizableConfig}
          draggable={props.draggable}
          draggableConfig={props.draggableConfig}
          destroyOnClose={props.destroyOnClose}
        >
          {props.modalBody}
        </Modal>
      </>
    );
  },
);

export default ModalTrigger;
